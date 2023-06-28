#!/bin/python

import sys

import openstack

import common
import conf

# create a connection object
conn = openstack.connect(cloud='openstack')

# Get a list of all the bmnodes
baremetalnodes = conn.baremetal.nodes(fields=["uuid", "name", "extra", "power_state", "provision_state"])
env_baremetalnodes = [node for node in baremetalnodes if node.extra.get(common.ENV_FIELD) == conf.ENVNAME ]

for node in env_baremetalnodes:
    print("Clearing env data ", node["uuid"], node["name"])
    conn.baremetal.update_node(node["uuid"], extra={common.ENV_FIELD: "", common.ROLE_FIELD: ""})
    if node["provision_state"] == "active":
        print("Undeploying ", node["uuid"], node["name"])
        conn.baremetal.set_node_provision_state(node["uuid"], "deleted")

# TODO: check description
fips = conn.network.ips(floating_network_id='71bdf502-a09f-4f5f-aba2-203fe61189dc')
for fip in fips:
    for fp in conn.network.floating_ip_port_forwardings(fip["id"]):
        conn.network.delete_floating_ip_port_forwarding(fip["id"], fp["id"])
    conn.network.delete_ip(fip["id"])

# (esienv) [derekh@laptop esi]$ openstack router remove subnet router-okdci subnet-okdci_1bm
# (esienv) [derekh@laptop esi]$ openstack router remove subnet router-okdci subnet-okd
# (esienv) [derekh@laptop esi]$ openstack router delete router-okdci 

