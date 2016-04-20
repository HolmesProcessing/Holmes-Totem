#!/bin/bash

if [[ $INIT_SYSTEM = "upstart" ]]; then
    template="install/init/upstart.totem.template"
    initpath="/etc/systemd/system/holmes-totem.service"
    function enable_script {
        sudo initctl reload-configuration
        sudo service holmes-totem start
    }
else
    template="install/init/systemd.totem.template"
    initpath="/etc/init/holmes-totem.conf"
    function enable_script {
        sudo systemctl enable holmes-totem.service
        sudo systemctl start holmes-totem.service
    }
fi

template=$(cat "$template" | sed -e 's~INSTALL_DIRECTORY~'"${OPT[path]}"'~')
echo "$template" | sudo tee "$initpath" >/dev/null
enable_script
