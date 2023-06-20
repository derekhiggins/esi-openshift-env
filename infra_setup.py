import argparse
import ipaddress
import subprocess
import sys
import os

from jinja2 import Environment, FileSystemLoader

import openstack

import conf

ENV_FIELD = "envname"
ROLE_FIELD = "role"
PROVISION_STATE_AVAILABLE = "available"

def get_ip_address(subnet, index):
    ip_range = ipaddress.IPv4Network(subnet)
    ip_address = str(ip_range[index])
    return ip_address

def get_or_create_fip(conn, description):
    floating_ips = conn.network.ips(floating=True)
    for ip in floating_ips:
        if ip["description"] == description:
            break
    else:
        # TODO: find the ID of floating ip network "external"
        ip = conn.network.create_ip(floating_network_id="71bdf502-a09f-4f5f-aba2-203fe61189dc", description=description)
    return ip

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("envname", help="name of the environment")
    return parser.parse_args()

def allocate_nodes(conn):
    roles = {"prov": [], "master": [], "worker": []}

    nodes = list(conn.baremetal.nodes(fields=["uuid", "name", "extra", "power_state",
                                   "provision_state"]))

    unallocated_nodes = [node for node in nodes if node.extra.get(ENV_FIELD, "") == ""
                                        and node["provision_state"] == PROVISION_STATE_AVAILABLE]

    env_nodes = [node for node in nodes if node.extra.get(ENV_FIELD) == conf.ENVNAME]

    for node in env_nodes:
        role = node.extra[ROLE_FIELD]
        if role in roles:
            roles[role].append(node)

    if not roles["prov"]:
        roles["prov"] = unallocated_nodes.pop(0)
        conn.baremetal.update_node(roles["prov"]["uuid"],
                                   extra={ENV_FIELD: conf.ENVNAME, ROLE_FIELD: "prov"})

    for role, nodes in roles.items():
        num_needed = {"master": conf.NUM_MASTERS, "worker": conf.NUMWORKERS}.get(role, 1)
        for i in range(num_needed - len(nodes)):
            nodes.append(unallocated_nodes.pop(0))
            conn.baremetal.update_node(nodes[-1]["uuid"],
                               extra={ENV_FIELD: conf.ENVNAME, ROLE_FIELD: role})

    # TODO: provision hosts that are available but not active

    return roles["prov"], roles["master"], roles["worker"]


def get_or_create_network(conn, name, create=True, network_name=None, subnet_name=None):
    if network_name == None:
        network_name = "net-"+name
    if subnet_name == None:
        subnet_name = "subnet-"+name

    net = subnet = None
    for n in conn.network.networks():
        if n["name"] == network_name:
            net=n

    for sn in conn.network.subnets():
        if sn["name"] == subnet_name:
            subnet=sn


    if create:
        if not net:
            net = conn.network.create_network(name=network_name, port_security_enabled=False)
        if not subnet:
            if "bm" in network_name:
                # Needs a gateway as prov host is using X.X.X.1
                subnet = conn.network.create_subnet(name=subnet_name, network_id=net["id"], ip_version=4, cidr=conf.EXTNETWORK,
                    gateway_ip=get_ip_address(conf.EXTNETWORK, -2), dns_nameservers=[get_ip_address(conf.EXTNETWORK, 1)],
                    allocation_pools=[{"start": get_ip_address(conf.EXTNETWORK, 20), "end": get_ip_address(conf.EXTNETWORK, 100)}])
            elif "pr" in network_name:
                subnet = conn.network.create_subnet(name=subnet_name, network_id=net["id"], ip_version=4, cidr="172.22.0.0/24", enable_dhcp=False)
            elif "okd" == network_name:
                ACCESSNETWORK = "192.168.55.0/24"
                subnet = conn.network.create_subnet(name=subnet_name, network_id=net["id"], ip_version=4, cidr=ACCESSNETWORK, allocation_pools=[{"start": get_ip_address(ACCESSNETWORK, 20), "end": get_ip_address(ACCESSNETWORK, 100)}], dns_nameservers=["8.8.8.8"])
    return net, subnet


def add_interface_to_router(conn, router, subnet_id):
    try:
        conn.network.add_interface_to_router(router, subnet_id)
    except openstack.exceptions.BadRequestException as e:
        if "Router already has a port on subnet" not in e.details:
            raise

def runcmd(cmd: str) -> (str, int):
    exit_code = 0
    try:
        print("  ", cmd)
        output = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        output = e.output
        exit_code = e.returncode
    return output, exit_code

def detach_trunk(node, portid):
    return runcmd(f'openstack esi node network detach {node} {portid}')

def delete_trunk(switch_port: str) -> (str, int):
    return runcmd(f'openstack esi trunk delete "{switch_port}"')

def create_trunk(switch_port, native, tagged):
    tagged = "".join([f" --tagged-networks {t}" for t in tagged])
    return runcmd(f'openstack esi trunk create --native-network {native} {tagged} "{switch_port}"')

def deploy(node, trunk_port_name):
    return runcmd(f'metalsmith deploy --image centos-image  --ssh-public-key ~/.ssh/id_ed25519.pub --resource-class baremetal --candidate {node} --no-wait --port "{trunk_port_name}"')

def manage_trunk(conn, bmnode, bmport, netokd, netpr, netbm, trunk_ports):
    switch = bmport["local_link_connection"]["switch_info"]
    switch_port = bmport["local_link_connection"]["port_id"]

    trunk_port_name = f'esi-{switch}-{switch_port}-{netpr["name"]}-trunk-port'
    bm_port_name = f'esi-{switch}-{switch_port}-{netbm["name"]}-sub-port'
    trunk_name = f"{switch}-{switch_port}"
    native = [netpr["provider:segmentation_id"]]
    tagged = [netbm["provider:segmentation_id"]]
    # TODO: role mightn't be set if new
    if bmnode.extra.get(ROLE_FIELD) == "prov":
        trunk_port_name = f"esi-{switch}-{switch_port}-okd-trunk-port"
        native = [netokd["provider:segmentation_id"]]
        tagged = [netpr["provider:segmentation_id"], netbm["provider:segmentation_id"]]

    print("setting up trunk ", trunk_port_name)
    trunk_port = trunk_ports.get(trunk_port_name)

    internal_info = bmport.get("internal_info")
    if internal_info:
        bmport_port = internal_info.get("tenant_vif_port_id")
        if bmport_port and trunk_port and bmport_port != trunk_port["id"]:
            print("Attached to the wrong port, detach")
            detach_trunk(bmnode["name"], trunk_port["id"])

    if trunk_port and len(set([subport["segmentation_id"] for subport in trunk_port["trunk_details"]["sub_ports"]]).symmetric_difference(tagged)) > 0:
        print("Deleting", trunk_port_name)
        delete_trunk(trunk_name)
        trunk_port = None

    if not trunk_port:
        print("Creating ", trunk_port_name)
        if bmnode.extra.get(ROLE_FIELD) == "prov":
            create_trunk(trunk_name, "okd", [netpr["name"], netbm["name"]])
        else:
            create_trunk(trunk_name, netpr["name"], [netbm["name"]])

    return trunk_port_name, bm_port_name


def main():
    args = parse_args()

    # create a connection object
    conn = openstack.connect(cloud='openstack')

    provisioning_nodes, master_nodes, worker_nodes = allocate_nodes(conn, conf.ENVNAME)

    netokd, subnetokd = get_or_create_network(conn, "okd", True, network_name="okd", subnet_name="subnet-okd")
    netpr, subnetpr = get_or_create_network(conn, conf.ENVNAME + "pr")
    netbm, subnetbm = get_or_create_network(conn, conf.ENVNAME + "bm")
    netext, subnetext = get_or_create_network(conn, "", False, network_name="external", subnet_name="subnet-external")

    for router in conn.network.routers():
        if router["name"] == "router-okdci":
            break
    else:
        # bm network needs a router
        router = conn.network.create_router(name="router-okdci", is_ha=False, external_gateway_info={'network_id': netext["id"]})

    add_interface_to_router(conn, router, subnet_id=subnetokd.id)
    add_interface_to_router(conn, router, subnet_id=subnetbm.id)

    bmports = conn.baremetal.ports(fields=["uuid", "address", "node_uuid", "local_link_connection", "internal_info"])
    bmports_by_node = {port["node_uuid"]: port for port in bmports}

    trunk_ports = {port["name"]: port for port in conn.network.ports() if port["name"]}

    env = Environment(loader=FileSystemLoader('.'))
    os.makedirs("resources/vlan-over-prov", exist_ok=True)

    rnodes = []
    prov_bm_port_name = ''
    for i, bmnode in enumerate(provisioning_nodes + master_nodes + worker_nodes):
        bmport = bmports_by_node[bmnode["uuid"]]
        trunk_port_name, bm_port_name = manage_trunk(conn, bmnode, bmport, netokd, netpr, netbm, trunk_ports)
        if bmnode["provision_state"] == PROVISION_STATE_AVAILABLE:
            deploy(bmnode["uuid"], trunk_port_name)

        if bmnode.extra.get(ROLE_FIELD) == "prov":
            prov_bm_port_name = bm_port_name
            prov_ext_port_name = trunk_port_name
            continue

        rnode = {}
        rnode["name"] = bmnode["name"]
        rnode["mac"] = bmport["address"]
        rnode["ip"] = get_ip_address(conf.EXTNETWORK, 20+i)
        rnode["id"] = bmnode["id"]
        rnodes.append(rnode)

        # Create a static net config for each nodes
        template = env.get_template('netconfig.yaml.j2')
        if not trunk_ports.get(bm_port_name):
            trunk_ports = {port["name"]: port for port in conn.network.ports() if port["name"]}
        output_str = template.render(bmvlanid=netbm["provider:segmentation_id"], bmmac=trunk_ports[bm_port_name]["mac_address"])
        with open("resources/vlan-over-prov/%s.yaml"%rnode["name"], "w") as fp:
            fp.write(output_str)

    bootstrap_port_name = f"{conf.ENVNAME} BOOTSTRAP"
    if not trunk_ports.get(bootstrap_port_name):
        conn.network.create_port(name=bootstrap_port_name, network_id=netbm["id"], mac_address="52:54:00:B0:07:4F", fixed_ips=[{'subnet_id': subnetbm["id"], 'ip_address': get_ip_address(conf.EXTNETWORK, 101) }])
    prov_port_name = f"{conf.ENVNAME} PROV"
    if not trunk_ports.get(prov_port_name):
        conn.network.create_port(name=prov_port_name, network_id=netbm["id"], fixed_ips=[{'subnet_id': subnetbm["id"], 'ip_address': get_ip_address(conf.EXTNETWORK, 1) }])
    ingress_port_name = f"{conf.ENVNAME} IngressVIP"
    if not trunk_ports.get(ingress_port_name):
        conn.network.create_port(name=ingress_port_name, network_id=netbm["id"], fixed_ips=[{'subnet_id': subnetbm["id"], 'ip_address': get_ip_address(conf.EXTNETWORK, 4) }])
    api_port_name = f"{conf.ENVNAME} APIVIP"
    if not trunk_ports.get(api_port_name):
        conn.network.create_port(name=api_port_name, network_id=netbm["id"], fixed_ips=[{'subnet_id': subnetbm["id"], 'ip_address': get_ip_address(conf.EXTNETWORK, 5) }])

    trunk_ports = {port["name"]: port for port in conn.network.ports() if port["name"]}

    provip = get_or_create_fip(conn, "{conf.ENVNAME} access")
    # create the port forwarding rule for ssh access to the provisioning node
    try:
        port_forwarding_rule = conn.network.create_port_forwarding(
            floatingip_id=provip["id"],
            internal_port_id=trunk_ports[prov_ext_port_name]["id"],
            internal_ip_address=trunk_ports[prov_ext_port_name]["fixed_ips"][0]["ip_address"],
            internal_port='22', external_port='22', protocol='tcp'
        )
    except openstack.exceptions.BadRequestException as e:
        if "A duplicate port forwarding" not in e.details:
            raise

    clusterip = get_or_create_fip(conn, "{conf.ENVNAME} cluster access")
    # create the port forwarding rules cluster access
    try:
        port_forwarding_rule = conn.network.create_port_forwarding(
            floatingip_id=clusterip["id"],
            internal_port_id=trunk_ports[api_port_name]["id"],
            internal_ip_address=trunk_ports[api_port_name]["fixed_ips"][0]["ip_address"],
            internal_port='6443', external_port='6443', protocol='tcp'
        )
        port_forwarding_rule = conn.network.create_port_forwarding(
            floatingip_id=clusterip["id"],
            internal_port_id=trunk_ports[ingress_port_name]["id"],
            internal_ip_address=trunk_ports[ingress_port_name]["fixed_ips"][0]["ip_address"],
            internal_port='443', external_port='443', protocol='tcp'
        )
    except openstack.exceptions.BadRequestException as e:
        if "A duplicate port forwarding" not in e.details:
            raise

    # create some files needed on the provisioning host
    for content_file in [ 'bm.json', 'dnsmasq.conf']:
        template = env.get_template(content_file+".j2")
        output_str = template.render(nodes=rnodes)
        with open("resources/"+content_file, "w") as fp:
            fp.write(output_str)

    # some vars
    with open("resources/vars.sh", "w") as fp:
        fp.write("export VLANID_PR=%s\n"%netpr["provider:segmentation_id"])
        fp.write("export VLANID_BM=%s\n"%netbm["provider:segmentation_id"])
        fp.write("export PROV_BM_MAC=%s\n"%trunk_ports[prov_bm_port_name]["mac_address"])
        fp.write("export NUM_WORKERS=%s\n"%conf.NUMWORKERS)

if __name__ == "__main__":
    main()
