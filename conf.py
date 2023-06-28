# CI_TOKEN - **REQUIRED**
# You can get this token from https://console-openshift-console.apps.ci.l2s4.p1.openshiftapps.com/
# by clicking on your name in the top right corner and coping the login
# command (the token is part of the command)
CI_TOKEN='sha256~S1l_GLjdkhdyGu5FxPhIsgNzQ29gw5TgJ2qgs8yB7-4'

# Release image to Use e.g.
OPENSHIFT_RELEASE_IMAGE="quay.io/okd/scos-release:4.13.0-0.okd-scos-2023-05-25-085822"

# Name on the environment being setup, should be uniq if using
# a single openstack project to create multiple envs
ENVNAME="okdci_1"

# Openstack networks to setup in
# Openstack externel network
EXTNETWORK = "192.168.112.0/24"

# Jumphos/Provisioning node network
ACCESSNETWORK = "192.168.55.0/24"

# Cluster Name/Domain, externel access requires that DNS be setup to the "cluster access" floating ip(see $CLUSTER_FIP)
# from the DNS entries) api.$CLUSTER_NAME.$BASE_DOMAIN, *.apps.$CLUSTER_NAME.$BASE_DOMAIN
CLUSTER_NAME="ci-01"
BASE_DOMAIN="okd.on.massopen.cloud"

#
NUM_MASTERS = 3
NUM_WORKERS = 2

