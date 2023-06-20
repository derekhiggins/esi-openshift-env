set +x
export CI_TOKEN='sha256~...........'
set -x

. vars.sh

export CLUSTER_NAME="ci-01"
export BASE_DOMAIN="okd.on.massopen.cloud"


#export IRONIC_LOCAL_IMAGE=quay.io/higginsd/testimage:ironic-image-scos
export EXTERNAL_SUBNET=192.168.112.0/24
export OPENSHIFT_RELEASE_IMAGE=quay.io/okd/scos-release:4.13.0-0.okd-scos-2023-05-25-085822
export ENABLE_LOCAL_REGISTRY=true
export IP_STACK=v4
export BMC_DRIVER=ipmi
export NETWORK_CONFIG_FOLDER=/home/centos/dev-scripts/network-configs/vlan-over-prov

export NODES_FILE="/home/centos/dev-scripts/bm.json"
export NODES_PLATFORM=baremetal
export MANAGE_BR_BRIDGE=n
export MANAGE_INT_BRIDGE=n
export CLUSTER_PRO_IF="eno1"
export EXTERNALMACADDRESS=52:54:00:B0:07:4F


export PRO_IF="eth0.$VLANID_PR"
export INT_IF="eth0.$VLANID_BM"

