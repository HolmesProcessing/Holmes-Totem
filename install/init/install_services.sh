#!/bin/bash

if [[ $INIT_SYSTEM = "upstart" ]]; then
    template="install/init/upstart.services.template"
    initpath="/etc/systemd/system/holmes-totem-services.service"
    function enable_script {
        sudo initctl reload-configuration
        sudo service holmes-totem-services start
    }
else
    template="install/init/systemd.services.template"
    initpath="/etc/init/holmes-totem-services.conf"
    function enable_script {
        sudo systemctl enable holmes-totem-services.service
        sudo systemctl start holmes-totem-services.service
    }
fi

template=$(cat "$template" | sed -e 's~INSTALL_DIRECTORY~'"${OPT[path]}"'~')
echo "$template" | sudo tee "$initpath" >/dev/null
enable_script
