#!/bin/bash

# grab upstart scripts and substitute installation directory
TOTEM_SCRIPT=$(cat "$1"/install/init/systemd.totem.template)
TOTEM_SCRIPT=$(echo "$TOTEM_SCRIPT" | sed -e 's~INSTALL_DIRECTORY~'$2'~')
SERVICE_SCRIPT=$(cat "$1"/install/init/systemd.services.template)
SERVICE_SCRIPT=$(echo "$SERVICE_SCRIPT" | sed -e 's~INSTALL_DIRECTORY~'$2'~')

echo "$TOTEM_SCRIPT" | tee "/etc/systemd/system/holmes-totem.service"
echo "$SERVICE_SCRIPT" | tee "/etc/systemd/system/holmes-totem-services.service"

systemctl enable "holmes-totem.service"
systemctl enable "holmes-totem-services.service"

systemctl start "holmes-totem-services.service"
systemctl start "holmes-totem.service"
