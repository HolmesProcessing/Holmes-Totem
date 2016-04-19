#!/bin/bash
# $1 = $START_PWD
# $2 = $INSTALL_DIRECTORY
# $3 = $OP_INSTALL_SERVICES

# grab upstart scripts and substitute installation directory
if [[ $3 -eq 1 ]]; then
    SERVICE_SCRIPT=$(cat "$1"/install/init/systemd.services.template)
    SERVICE_SCRIPT=$(echo "$SERVICE_SCRIPT" | sed -e 's~INSTALL_DIRECTORY~'$2'~')
fi
TOTEM_SCRIPT=$(cat "$1"/install/init/systemd.totem.template)
TOTEM_SCRIPT=$(echo "$TOTEM_SCRIPT" | sed -e 's~INSTALL_DIRECTORY~'$2'~')

if [[ $3 -eq 1 ]]; then
    echo "$SERVICE_SCRIPT" | tee "/etc/systemd/system/holmes-totem-services.service" >/dev/null
fi
echo "$TOTEM_SCRIPT" | tee "/etc/systemd/system/holmes-totem.service" >/dev/null

if [[ $3 -eq 1 ]]; then
    systemctl enable "holmes-totem-services.service"
fi
systemctl enable "holmes-totem.service"

sleep 2

if [[ $3 -eq 1 ]]; then
    systemctl start "holmes-totem-services.service"
fi
systemctl start "holmes-totem.service"
