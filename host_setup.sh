#!/bin/bash -x

IP=$1

scp -r resources config_centos.sh pull_secret.json clouds.yaml centos@$IP:

ssh centos@$IP <<-EOF
set -x
sudo dnf install -y git make podman tmux python3-virtualenv python39 net-tools ipmitool

rm -rf dev-scripts/network-configs/vlan-over-prov

[ -e dev-scripts ] || git clone https://github.com/openshift-metal3/dev-scripts.git
cd dev-scripts

cp ~/config_centos.sh ~/pull_secret.json ~/resources/bm.json ~/resources/vars.sh  ~/dev-scripts
cp -r ~/resources/vlan-over-prov ~/dev-scripts/network-configs/vlan-over-prov

. ~/resources/vars.sh

sudo nmcli c s | grep -e ostest -e vlan | awk '{print \$1}' | sudo xargs -t nmcli c del

sudo nmcli connection add type vlan con-name eth0.\$VLANID_PR dev eth0 id \$VLANID_PR ipv4.method disabled ipv6.method disabled
sudo nmcli connection add type vlan con-name eth0.\$VLANID_BM dev eth0 id \$VLANID_BM ipv4.method disabled ipv6.method disabled

#sudo podman pull quay.io/metal3-io/ironic
#sudo podman rm -f dnsmasqbm
#sudo podman run --name dnsmasqbm -d --privileged --net host -v ~/resources:/conf quay.io/metal3-io/ironic dnsmasq -C /conf/dnsmasq.conf -d

cd ~
[ -e virtualbmc ] || git clone https://github.com/tzumainn/virtualbmc.git -b tzumainn-hack
cd virtualbmc/
[ -e venv ] || virtualenv-3.6 --python python3.9 venv
. venv/bin/activate
pip install -r requirements.txt 
pip install .

echo -e '[default]\nconfig_dir=/home/centos/.vbmc/conf/\nserver_response_timeout=20000' > ~/.vbmc/virtualbmc.conf
echo -e '[log]\nlogfile=/home/centos/.vbmc/virtualbmc.log\ndebug=True' >> ~/.vbmc/virtualbmc.conf

sed -e 's/openstack:/overcloud:/g' ~/clouds.yaml > clouds.yaml

killall -9 vbmcd
rm -rf ~/.vbmc/conf ~/.vbmc/master.pid
mkdir -p .vbmc
cp -r ~/resources/vbmc ~/.vbmc/conf
vbmcd


EOF


