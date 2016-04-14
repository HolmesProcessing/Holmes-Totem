#!/bin/bash

# grab upstart scripts and substitute installation directory
TOTEM_SCRIPT=$(cat "$1"/install/init/upstart.totem.template)
TOTEM_SCRIPT=$(echo "$TOTEM_SCRIPT" | sed -e 's~INSTALL_DIRECTORY~'$2'~')
SERVICE_SCRIPT=$(cat "$1"/install/init/upstart.services.template)
SERVICE_SCRIPT=$(echo "$SERVICE_SCRIPT" | sed -e 's~INSTALL_DIRECTORY~'$2'~')

echo "$TOTEM_SCRIPT" | tee "/etc/init/holmes-totem.conf"
echo "$SERVICE_SCRIPT" | tee "/etc/init/holmes-totem-services.conf"

initctl reload-configuration

service "holmes-totem-services" start
service "holmes-totem" start
