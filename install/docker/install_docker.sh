#!/bin/bash

# install docker itself
if [[ $DOCKER -eq 0 ]]; then
    info "> Installing Docker."
    
    # sort out which program to use for download
    $(which curl &>/dev/null)
    cmd=""
    if [[ $? -eq 0 ]]; then
        cmd="curl -sSL"
    else
        $(which wget &>/dev/null)
        if [[ $? -eq 0 ]]; then
            cmd="wget -qO-"
        else
            sudo apt-get update
            sudo apt-get install curl
            cmd="curl -sSL"
        fi
    fi
    
    # get script and install docker
    script=$($cmd https://get.docker.com/)
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
    
    # sort out which program to use for download
    $(which curl &>/dev/null)
    cmd=""
    if [[ $? -eq 0 ]]; then
        cmd="curl -L"
    else
        $(which wget &>/dev/null)
        if [[ $? -eq 0 ]]; then
            cmd="wget -qO-"
        else
            sudo apt-get update
            sudo apt-get install curl
            cmd="curl -L"
        fi
    fi
    
    # get script and install docker-compose
    sudo sh -c "$cmd https://github.com/docker/compose/releases/download/1.7.0/docker-compose-`uname -s`-`uname -m` > /usr/local/bin/docker-compose"
    sudo chmod +x /usr/local/bin/docker-compose
    info ""
fi

# Start Docker daemon
info "> Ensuring Docker daemon started."
service docker start
info ""
