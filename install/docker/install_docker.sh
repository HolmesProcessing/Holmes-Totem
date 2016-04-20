#!/bin/bash

info "> Installing Docker."
sudo apt-get install curl
curl -sSL https://get.docker.com/ | /bin/sh
info ""

info "> Attempting to start Docker."
if [[ $INIT_SYSTEM = "systemd" ]]; then
    sudo systemctl start docker.service
else
    sudo service docker start
fi
info ""
