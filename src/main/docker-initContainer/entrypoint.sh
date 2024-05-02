#!/usr/bin/env sh
# set -uo pipefail -o functrace -o xtrace
# set -uo pipefail

echo "Init Container to install the keycloak-kubernetes-authenticator"
echo "It installs them into '/opt/keycloak/providers'"

cp /keycloak-kubernetes-authenticator.jar /opt/keycloak/providers
