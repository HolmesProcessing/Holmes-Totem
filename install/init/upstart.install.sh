#!/bin/bash
# $1 = $START_PWD
# $2 = $INSTALL_DIRECTORY
# $3 = $OP_INSTALL_SERVICES

# grab upstart scripts and substitute installation directory
if [[ $3 -eq 1 ]]; then
    SERVICE_SCRIPT=$(cat "$1"/install/init/upstart.services.template)
    SERVICE_SCRIPT=$(echo "$SERVICE_SCRIPT" | sed -e 's~INSTALL_DIRECTORY~'$2'~')
fi
TOTEM_SCRIPT=$(cat "$1"/install/init/upstart.totem.template)
TOTEM_SCRIPT=$(echo "$TOTEM_SCRIPT" | sed -e 's~INSTALL_DIRECTORY~'$2'~')

if [[ $3 -eq 1 ]]; then
    echo "$SERVICE_SCRIPT" | tee "/etc/init/holmes-totem-services.conf" >/dev/null
fi
echo "$TOTEM_SCRIPT" | tee "/etc/init/holmes-totem.conf" >/dev/null

initctl reload-configuration

if [[ $3 -eq 1 ]]; then
    service "holmes-totem-services" start
fi
service "holmes-totem" start
