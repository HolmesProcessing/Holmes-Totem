#!/bin/bash

info "> Installing Docker-Compose."
sudo apt-get install curl
sudo sh -c "curl -L https://github.com/docker/compose/releases/download/1.7.0/docker-compose-`uname -s`-`uname -m` > /usr/local/bin/docker-compose"
sudo chmod +x /usr/local/bin/docker-compose
info ""
