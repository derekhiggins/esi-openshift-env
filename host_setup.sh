#!/bin/bash -x

IP=$1

scp -r resources config_centos.sh pull_secret.json centos@$IP:

ssh centos@$IP <<-EOF
set -x
sudo dnf install -y git make podman tmux

rm -rf dev-scripts/network-configs/vlan-over-prov

[ -e dev-scripts ] || git clone https://github.com/openshift-metal3/dev-scripts.git
cd dev-scripts

cp ~/config_centos.sh ~/pull_secret.json ~/resources/bm.json ~/resources/vars.sh  ~/dev-scripts
cp -r ~/resources/vlan-over-prov ~/dev-scripts/network-configs/vlan-over-prov

. ~/resources/vars.sh

sudo nmcli c s | grep -e ostest -e vlan | awk '{print \$1}' | sudo xargs -t nmcli c del

sudo nmcli connection add type vlan con-name eth0.\$VLANID_PR dev eth0 id \$VLANID_PR
sudo nmcli connection add type vlan con-name eth0.\$VLANID_BM dev eth0 id \$VLANID_BM

#sudo podman pull quay.io/metal3-io/ironic
#sudo podman rm -f dnsmasqbm
#sudo podman run --name dnsmasqbm -d --privileged --net host -v ~/resources:/conf quay.io/metal3-io/ironic dnsmasq -C /conf/dnsmasq.conf -d

EOF


