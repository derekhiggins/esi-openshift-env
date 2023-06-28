This repository contains scripts used to setup the infrastructre on ESI on which to provision a openshift cluster

There are a few files to be familiar with

**setup.sh**: Run this to setup dependencies on the local host

**rc**: run command file to activate the client environment

**conf.py**: Edit configurable options in here

**clouds.yaml**: should be created by the user to allow access to a "openstack" cloud

**infra_setup.py**: Run infra_setup.py to setup all of the openstack resources required for
your env

**host_setup.s**h: configures the provisioning node (provisioned by infra_setup.py) ready to
run dev-scripts



Once all 3 steps are done, the users can ssh to the provisioning node, find IP in resources/config_centos.sh
(see $PROV_FIP). The ssh to this IP and run dev-scrips as usual

The expected usage would look something like this
```
$ ./setup.sh
$ . rc
(esienv) $ vim conf.py # Edit any params
\# Ensure clouds.yaml is configured
(esienv) $ openstack --os-cloud openstack  baremetal node list
(esienv) $ infra_setup.py
(esienv) $ host_setup.sh

ssh centos@$PROV_FIP
$ cd dev-scripts
$ make
```
