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
    for net in conn.network.networks():
        if net["name"] == network_name:
            return net

    # TODO: Add subnet
    if create:
        return conn.network.create_network(name=network_name, port_security_enabled=False)

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

def manage_trunk(conn, bmnode, bmport, netext, netpr, netbm, trunk_ports):
    switch = bmport["local_link_connection"]["switch_info"]
    switch_port = bmport["local_link_connection"]["port_id"]

    trunk_port_name = f'esi-{switch}-{switch_port}-{netpr["name"]}-trunk-port'
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

    attach = False


    internal_info = bmport.get("internal_info")
    if internal_info:
        bmport_port = internal_info.get("tenant_vif_port_id")
        if bmport_port and trunk_port and bmport_port != trunk_port["id"]:
            print("Attached to the wrong port, detach")
            detach_trunk(bmnode["name"], trunk_port["id"])
            attach = True

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
        attach = True

    if attach:
        print("Attaching")
        attach_trunk(trunk_port_name, bmnode["name"])


def main():
    args = parse_args()

    # create a connection object
    conn = openstack.connect(cloud='openstack')

    provisioning_nodes, master_nodes, worker_nodes = allocate_nodes(conn, args.envname, args.numworkers)

    netext = get_or_create_network(conn, "okd", False)
    netpr = get_or_create_network(conn, args.envname + "pr")
    netbm = get_or_create_network(conn, args.envname + "bm")

    bmports = conn.baremetal.ports(fields=["uuid", "address", "node_uuid", "local_link_connection", "internal_info"])
    bmports_by_node = {port["node_uuid"]: port for port in bmports}

    trunk_ports = {port["name"]: port for port in conn.network.ports() if port["name"]}

    env = Environment(loader=FileSystemLoader('.'))
    try: os.makedirs("resources/vlan-over-prov")
    except: pass

    rnodes = []
    hex_string = format(int(netbm["provider:segmentation_id"]), '04X')
    # setting the second-least-significant bit of the first octet to mark as locally administered
    # then encode the vlan number and a sequence
    bmmac_prefix = "03:00:00:" + hex_string[:2] + ':' + hex_string[2:]
    for i, bmnode in enumerate(provisioning_nodes + master_nodes + worker_nodes):
        bmport = bmports_by_node[bmnode["uuid"]]
        manage_trunk(conn, bmnode, bmport, netext, netpr, netbm, trunk_ports)

        if bmnode.extra.get(ROLE_FIELD) == "prov":
            continue

        rnode = {}
        rnode["name"] = bmnode["name"]
        rnode["mac"] = bmport["address"]
        rnode["bmmac"] = f"{bmmac_prefix}:{i:02x}"
        rnode["ip"] = f"192.168.111.{20+i}"
        rnodes.append(rnode)

        # Create a static net config for each nodes
        template = env.get_template('netconfig.yaml.j2')
        output_str = template.render(bmvlanid=netbm["provider:segmentation_id"], bmmac=rnode["bmmac"])
        with open("resources/vlan-over-prov/%s.yaml"%rnode["name"], "w") as fp:
            fp.write(output_str)
            


    # TODO: deploy centos on the prov host and assign it a floating ip
    # metalsmith deploy --image centos-image  --ssh-public-key ~/.ssh/id_rsa.pub --resource-class baremetal --candidate <node>
    # openstack floating ip create --port <port> external


    # For create a bm.json file containing each bmnode
    template = env.get_template('bm.json.j2')
    output_str = template.render(nodes=rnodes)
    with open("resources/bm.json", "w") as fp:
        fp.write(output_str)

    # For create a bm.json file containing each bmnode
    template = env.get_template('dnsmasq.conf.j2')
    output_str = template.render(nodes=rnodes)
    with open("resources/dnsmasq.conf", "w") as fp:
        fp.write(output_str)

    # some vars 
    with open("resources/vars.sh", "w") as fp:
        fp.write("export VLANID_PR=%s\n"%netpr["provider:segmentation_id"])
        fp.write("export VLANID_BM=%s\n"%netbm["provider:segmentation_id"])
        fp.write("export NUM_WORKERS=%s\n"%args.numworkers)

if __name__ == "__main__":
    main()
