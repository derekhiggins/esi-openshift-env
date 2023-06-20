#!/bin/bash -x

IP=$1

scp -rC resources config_centos.sh pull_secret.json clouds.yaml centos@$IP:

ssh centos@$IP <<-EOF
set -x
sudo dnf install -y git make podman tmux python3-virtualenv python39 net-tools ipmitool httpd-tools

rm -rf dev-scripts/network-configs/vlan-over-prov

[ -e dev-scripts ] || git clone https://github.com/openshift-metal3/dev-scripts.git
cd dev-scripts
#curl https://goodsquishy.com/upload/191b0e9933b668e9b7fe | git am -

cp ~/config_centos.sh ~/pull_secret.json ~/resources/bm.json ~/resources/vars.sh  ~/dev-scripts
cp -r ~/resources/vlan-over-prov ~/dev-scripts/network-configs/vlan-over-prov

. ~/resources/vars.sh

sudo nmcli c s | grep -e ci-01 -e vlan | awk '{print \$1}' | sudo xargs -t nmcli c del

echo -e 'nameserver 192.168.112.1\nnameserver 8.8.8.8' | sudo tee /etc/resolv.conf
sudo nmcli c modify "System eth0" ipv4.dns 192.168.112.1 ipv4.ignore-auto-dns yes

sudo nmcli connection add type vlan con-name eth0.\$VLANID_PR dev eth0 id \$VLANID_PR ipv4.method disabled ipv6.method disabled

sudo nmcli con add type bridge con-name ci-01bm ifname ci-01bm ipv4.method manual ipv4.address "192.168.112.1/24" ipv4.gateway "192.168.112.254" ipv4.dns 192.168.112.1 ipv4.ignore-auto-dns yes
sudo nmcli connection add type vlan con-name eth0.\$VLANID_BM dev eth0 id \$VLANID_BM ipv4.method disabled ipv6.method disabled 802-3-ethernet.cloned-mac-address \$PROV_BM_MAC master ci-01bm

sudo podman pull quay.io/metal3-io/ironic
sudo podman rm -f dnsmasqbm
sudo podman run --name dnsmasqbm -d --privileged --net host -v ~/resources:/conf quay.io/metal3-io/ironic dnsmasq -C /conf/dnsmasq.conf -d -q

cd ~
[ -e sushy-tools ] || git clone https://github.com/derekhiggins/sushy-tools.git -b esi
cd sushy-tools/
[ -e venv ] || virtualenv-3.6 --python python3.9 venv
. venv/bin/activate
pip install -r requirements.txt
pip install . python-openstackclient python-ironicclient

mkdir -p ~/.sushy-tools
echo 'SUSHY_EMULATOR_LIBVIRT_URI = "qemu+ssh://root@localhost/system?&keyfile=/root/ssh/id_rsa_virt_power&no_verify=1&no_tty=1"' > ~/.sushy-tools/conf.py
echo -e 'SUSHY_EMULATOR_IGNORE_BOOT_DEVICE = False\nSUSHY_EMULATOR_VMEDIA_VERIFY_SSL = False' >> ~/.sushy-tools/conf.py
echo -e "SUSHY_EMULATOR_AUTH_FILE = '\$HOME/.sushy-tools/htpasswd'" >> ~/.sushy-tools/conf.py
echo -e "SUSHY_EMULATOR_IRONIC_CLOUD = 'openstack'" >> ~/.sushy-tools/conf.py
htpasswd -Bbn admin password > ~/.sushy-tools/htpasswd


#echo -e '[default]\nconfig_dir=/home/centos/.vbmc/conf/\nserver_response_timeout=20000' > ~/.vbmc/virtualbmc.conf
#echo -e '[log]\nlogfile=/home/centos/.vbmc/virtualbmc.log\ndebug=True' >> ~/.vbmc/virtualbmc.conf

#sed -e 's/openstack:/overcloud:/g' ~/clouds.yaml > clouds.yaml

#killall -9 vbmcd
#rm -rf ~/.vbmc/conf ~/.vbmc/master.pid
#mkdir -p ~/.vbmc
#cp -r ~/resources/vbmc ~/.vbmc/conf
#vbmcd


EOF
