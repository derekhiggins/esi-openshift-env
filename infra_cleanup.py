#!/bin/python

import sys

import openstack

import conf


envname = sys.argv[1]

# create a connection object
conn = openstack.connect(cloud='openstack')

# Get a list of all the bmnodes
baremetalnodes = conn.baremetal.nodes(fields=["uuid", "name", "extra", "power_state", "provision_state"])
env_baremetalnodes = [node for node in baremetalnodes if node.extra.get(conf.ENVFIELD) == envname ]

for node in env_baremetalnodes:
    print("Clearing env data ", node["uuid"], node["name"])
    conn.baremetal.update_node(node["uuid"], extra={conf.ENVFIELD: "", conf.ROLEFIELD: ""})
    if node["provision_state"] == "active":
        print("Undeploying ", node["uuid"], node["name"])
        conn.baremetal.set_node_provision_state(node["uuid"], "deleted")

for FIPID in $(openstack floating ip list | grep None | awk '{print $2}') ; do 
    for PFID in $(openstack floating ip port forwarding list $FIPID | awk '{print $2}') ; do
        echo $FIPID $PFID
    done
done


# TODO
# openstack esi trunk delete 'switch1-tengigabitethernet 1/38'

#for net in conn.network.networks():
#    if net["name"] in [envname+"pr", envname+"bm"]:
#        conn.network.delete_network(net.id)
