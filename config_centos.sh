set +x
export CI_TOKEN='sha256~...........'
set -x

. vars.sh

export IRONIC_LOCAL_IMAGE=quay.io/higginsd/testimage:ironic-image-scos

export OPENSHIFT_RELEASE_IMAGE=registry.ci.openshift.org/origin/release-scos:4.13.0-0.okd-scos-2023-05-16-065457
export ENABLE_LOCAL_REGISTRY=true
export IP_STACK=v4
export BMC_DRIVER=ipmi
export NETWORK_CONFIG_FOLDER=/home/centos/dev-scripts/network-configs/vlan-over-prov

export NODES_FILE="/home/centos/dev-scripts/bm.json"
export NODES_PLATFORM=baremetal
#export MANAGE_BR_BRIDGE=y
export CLUSTER_PRO_IF="eno1"
#export ADDN_DNS="192.168.111.1"
#export MANAGE_INT_BRIDGE=y

export PRO_IF="eth0.$VLANID_PR"
export INT_IF="eth0.$VLANID_BM"

#export CLUSTER_NAME="${NAME%%.*}"
#export BASE_DOMAIN="ocpci.eng.rdu2.redhat.com"
#export EXTERNAL_SUBNET_V4="10.10.129.0/24"
#export PROVISIONING_HOST_EXTERNAL_IP=$IP
#export LOCAL_REGISTRY_DNS_NAME=host1.$NAME

