import argparse
import subprocess
import sys
import os

from jinja2 import Environment, FileSystemLoader


import openstack

ENV_FIELD = "envname"
ROLE_FIELD = "role"
PROVISION_STATE_AVAILABLE = "available"
NUM_MASTERS = 3


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("envname", help="name of the environment")
    parser.add_argument("--numworkers", type=int, default=2, help="number of worker nodes")
    return parser.parse_args()


def allocate_nodes(conn, envname, numworkers):
    roles = {"prov": [], "master": [], "worker": []}

    nodes = list(conn.baremetal.nodes(fields=["uuid", "name", "extra", "power_state",
                                   "provision_state"]))

    unallocated_nodes = [node for node in nodes if node.extra.get(ENV_FIELD, "") == ""
                                        and node["provision_state"] == PROVISION_STATE_AVAILABLE]

    env_nodes = [node for node in nodes if node.extra[ENV_FIELD] == envname]

    for node in env_nodes:
        role = node.extra[ROLE_FIELD]
        if role in roles:
            roles[role].append(node)

    if not roles["prov"]:
        roles["prov"] = unallocated_nodes.pop(0)
        conn.baremetal.update_node(roles["prov"]["uuid"],
                                   extra={ENV_FIELD: envname, ROLE_FIELD: "prov"})

    for role, nodes in roles.items():
        num_needed = {"master": NUM_MASTERS, "worker": numworkers}.get(role, 1)
        for i in range(num_needed - len(nodes)):
            nodes.append(unallocated_nodes.pop(0))
            conn.baremetal.update_node(nodes[-1]["uuid"],
                               extra={ENV_FIELD: envname, ROLE_FIELD: role})

    # TODO: provision hosts that are available but not active

    return roles["prov"], roles["master"], roles["worker"]


def get_or_create_network(conn, network_name, create=True):
    net = subnet = None
    for n in conn.network.networks():
        if n["name"] == network_name:
            net=n

    for sn in conn.network.subnets():
        if sn["name"] == "subnet-"+network_name:
            subnet=sn
    

    if create:
        if not net:
            net = conn.network.create_network(name=network_name, port_security_enabled=False)
        if not subnet:
            if "bm" in network_name:
                # Needs a gateway as prov host is using 192.168.111.1 
                subnet = conn.network.create_subnet(name="subnet-"+network_name, network_id=net["id"], ip_version=4, cidr="192.168.111.0/24",
                    gateway_ip="192.168.111.254", dns_nameservers=["192.168.111.1"],
                    allocation_pools=[{"start": "192.168.111.20", "end": "192.168.111.100"}])
            elif "pr" in network_name:
                subnet = conn.network.create_subnet(name="subnet-"+network_name, network_id=net["id"], ip_version=4, cidr="172.22.0.0/24", enable_dhcp=False)
    return net, subnet

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

def attach_trunk(port_uuid, node):
    return runcmd(f'openstack esi node network attach --port "{port_uuid}" {node}')

def deploy(node, trunk_port_name):
    return runcmd(f'metalsmith deploy --image centos-image  --ssh-public-key ~/.ssh/id_ed25519.pub --resource-class baremetal --candidate {node} --no-wait --port {trunk_port_name}')

def manage_trunk(conn, bmnode, bmport, netext, netpr, netbm, trunk_ports):
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
        native = [netext["provider:segmentation_id"]]
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

    provisioning_nodes, master_nodes, worker_nodes = allocate_nodes(conn, args.envname, args.numworkers)

    netext, subnetext = get_or_create_network(conn, "okd", False)
    netpr, subnetpr = get_or_create_network(conn, args.envname + "pr")
    netbm, subnetbm = get_or_create_network(conn, args.envname + "bm")

    bmports = conn.baremetal.ports(fields=["uuid", "address", "node_uuid", "local_link_connection", "internal_info"])
    bmports_by_node = {port["node_uuid"]: port for port in bmports}

    trunk_ports = {port["name"]: port for port in conn.network.ports() if port["name"]}

    env = Environment(loader=FileSystemLoader('.'))
    try: os.makedirs("resources/vlan-over-prov")
    except: pass

    rnodes = []
    # TODO: fix a possible dissconnect here between this and the port number in bm.json.j2
    ipmi_port = 6230
    prov_bm_port_name = ''
    for i, bmnode in enumerate(provisioning_nodes + master_nodes + worker_nodes):
        bmport = bmports_by_node[bmnode["uuid"]]
        trunk_port_name, bm_port_name = manage_trunk(conn, bmnode, bmport, netext, netpr, netbm, trunk_ports)
        if bmnode["provision_state"] == PROVISION_STATE_AVAILABLE:
            deploy(bmnode["uuid"], trunk_port_name)

        if bmnode.extra.get(ROLE_FIELD) == "prov":
            prov_bm_port_name = bm_port_name
            prov_ext_port_name = trunk_port_name
            continue

        rnode = {}
        rnode["name"] = bmnode["name"]
        rnode["mac"] = bmport["address"]
        rnode["ip"] = f"192.168.111.{20+i}"
        rnodes.append(rnode)

        # Create a static net config for each nodes
        template = env.get_template('netconfig.yaml.j2')
        output_str = template.render(bmvlanid=netbm["provider:segmentation_id"], bmmac=trunk_ports[bm_port_name]["mac_address"])
        with open("resources/vlan-over-prov/%s.yaml"%rnode["name"], "w") as fp:
            fp.write(output_str)
            
        # Create a vbmc config for each node
        template = env.get_template('vbmc_config.j2')
        output_str = template.render(uuid=bmnode["uuid"], ipmiport=str(ipmi_port))
        ipmi_port += 1
        try: os.makedirs("resources/vbmc/"+bmnode["uuid"])
        except: pass
        with open('resources/vbmc/%s/config'%bmnode["uuid"], "w") as fp:
            fp.write(output_str)

    if not trunk_ports.get("BOOTSTRAP"):
        # openstack port create --fixed-ip subnet=subnet-okd1bm,ip-address=192.168.111.50 --network okd1bm --mac-address 52:54:00:B0:07:4F BOOTSTRAP 
        conn.network.create_port(name="BOOTSTRAP", network_id=netbm["id"], mac_address="52:54:00:B0:07:4F", fixed_ips=[{'subnet_id': subnetbm["id"], 'ip_address': '192.168.111.101' }])

    floating_ips = conn.network.ips(floating=True)
    for ip in floating_ips:
        if ip["description"] == "okd1 access":
            break
    else:
        # TODO: find the ID of floating ip network "external"
        ip = conn.network.create_ip(floating_network_id="71bdf502-a09f-4f5f-aba2-203fe61189dc", description="okd1 access")

    # create the port forwarding rule
    # TODO: only do once
    #port_forwarding_rule = conn.network.create_port_forwarding(
    #    floatingip_id=ip["id"],
    #    internal_port_id=trunk_ports[prov_ext_port_name]["id"],
    #    internal_ip_address=trunk_ports[prov_ext_port_name]["fixed_ips"][0]["ip_address"],
    #    internal_port='22', external_port='22', protocol='tcp'
    #)

    if not trunk_ports.get("IngressVIP"):
        conn.network.create_port(name="IngressVIP", network_id=netbm["id"], fixed_ips=[{'subnet_id': subnetbm["id"], 'ip_address': '192.168.111.4' }])
    if not trunk_ports.get("APIVIP"):
        conn.network.create_port(name="APIVIP", network_id=netbm["id"], fixed_ips=[{'subnet_id': subnetbm["id"], 'ip_address': '192.168.111.5' }])

    for ip in floating_ips:
        if ip["description"] == "okd1 cluster access":
            break
    else:
        # TODO: find the ID of floating ip network "external"
        ip = conn.network.create_ip(floating_network_id="71bdf502-a09f-4f5f-aba2-203fe61189dc", description="okd1 cluster access")

    
    # create the port forwarding rules
    # TODO: only do once
    #port_forwarding_rule = conn.network.create_port_forwarding(
    #    floatingip_id=ip["id"],
    #    internal_port_id=trunk_ports["APIVIP"]["id"],
    #    internal_ip_address=trunk_ports["APIVIP"]["fixed_ips"][0]["ip_address"],
    #    internal_port='6443', external_port='6443', protocol='tcp'
    #)
    #port_forwarding_rule = conn.network.create_port_forwarding(
    #    floatingip_id=ip["id"],
    #    internal_port_id=trunk_ports["IngressVIP"]["id"],
    #    internal_ip_address=trunk_ports[prov_ext_port_name]["fixed_ips"][0]["ip_address"],
    #    internal_port='443', external_port='443', protocol='tcp'
    #)


    # create a some files needed on the provisioning host
    for template_file in [ 'bm.json.j2', 'dnsmasq.conf.j2']:
        template = env.get_template(template_file)
        output_str = template.render(nodes=rnodes)
        with open("resources/"+template_file, "w") as fp:
            fp.write(output_str)

    # some vars 
    with open("resources/vars.sh", "w") as fp:
        fp.write("export VLANID_PR=%s\n"%netpr["provider:segmentation_id"])
        fp.write("export VLANID_BM=%s\n"%netbm["provider:segmentation_id"])
        fp.write("export PROV_BM_MAC=%s\n"%trunk_ports[prov_bm_port_name]["mac_address"])
        fp.write("export NUM_WORKERS=%s\n"%args.numworkers)

if __name__ == "__main__":
    main()
