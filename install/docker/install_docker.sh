#!/bin/bash

# Add the gpg key for the apt repository
apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D

# Flavor specific treatment
if [[ $OS == "Ubuntu" ]]; then
    echo "deb https://apt.dockerproject.org/repo ubuntu-$1 main" > /etc/apt/sources.list.d/docker.list
    apt-get update && apt-get purge lxc-docker
else
    echo "deb https://apt.dockerproject.org/repo debian-$1 main" > /etc/apt/sources.list.d/docker.list
    apt-get update && apt-get purge lxc-docker* docker.io*
fi

# Install Docker, this requires the linux image extra as well
apt-get install -y linux-image-extra-$(uname -r)
apt-cache policy docker-engine
apt-get install -y docker-engine

# Install Docker Compose
# TODO this way is acutally discouraged, there seems to be a better way to do it
# see https://docs.docker.com/compose/install/
pip install docker-compose

# Start Docker daemon
service docker start
