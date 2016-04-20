#!/bin/bash

if [[ $KERNEL_VERSION_MAJOR -lt 3 ]] || [[ $KERNEL_VERSION_MAJOR -eq 3 && $KERNEL_VERSION_MINOR -lt 10 ]]; then
    error "> Your kernel version does not support running Docker, however Holmes-Totem default installation requires Docker."
    error "  If you wish to install Holmes-Totem with this script, please first upgrade your kernel (>=3.10)."
    exit 1
else
    if command -v docker >/dev/null 2>&1; then
        info "> Detected an existing Docker installation."
    else
        info "> No Docker installation found."
        . install/docker/install_docker.sh
    fi
    if command -v docker-compose >/dev/null 2>&1; then
        info "> Detected an existing docker-compose installation."
    else
        info "> No docker-dompose installation found."
        . install/docker/install_docker_compose.sh
    fi
    info ""
fi
info "> Assigning user 'totem' to the 'docker' group."
sudo usermod -aG docker totem
. install/init/install_services.sh
info ""
