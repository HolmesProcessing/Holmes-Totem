#!/bin/bash

# install docker itself
if [[ $DOCKER -eq 0 ]]; then
    info "> Installing Docker."
    script=$(curl -sSL https://get.docker.com/)
    if [[ $? -eq 127 ]]; then
        info "> curl not installed, trying wget."
        script=$(wget -qO- https://get.docker.com/)
        if [[ $? -eq 127 ]]; then
            info "> wget not installed either, trying to install curl and then retry."
            sudo apt-get update
            sudo apt-get install curl
            script=$(curl -sSL https://get.docker.com/)
        fi
    fi
    if [[ $? -ne 0 ]]; then
        error "> Unknown error happened trying to install Docker via curl and wget. Aborting installation."
        exit 1
    fi
    echo "$script" | /bin/sh
    info ""
fi

# install docker-compose
if [[ $DOCKER_COMPOSE -eq 0 ]]; then
    # TODO this way is actually discouraged, there seems to be a better way to do it
    # see https://docs.docker.com/compose/install/
    info "> Installing Docker-Compose."
    pip install docker-compose
    info ""
fi

# Start Docker daemon
info "> Ensuring Docker daemon started."
service docker start
info ""
