#!/bin/bash

# update existing infrastructure and add required dependencies
# enable https for apt
sudo apt-get update
echo ""
echo "${CYAN}> Installing base infrastructure dependencies.${ENDC}"
sudo apt-get install -y build-essential python-dev python-pip git apt-transport-https software-properties-common
echo ""

# (create &) update Docker user
if id -u "totem" >/dev/null 2>&1; then
    echo "${CYAN}> User 'totem' already exists, re-using it.${ENDC}"
else
    echo "${CYAN}> Creating user 'totem'.${ENDC}"
    sudo useradd totem
    # just useradd is not enough, sbt will crash because it can't
    # create its cash in ~/.sbt
    sudo /sbin/mkhomedir_helper totem
fi
echo "${CYAN}> Assigning user 'totem' to the 'docker' group.${ENDC}"
sudo usermod -aG docker totem

# prepare java 8
echo "${CYAN}> Preparing Oracle Java 8.${ENDC}"
echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | sudo debconf-set-selections
sudo add-apt-repository -y ppa:webupd8team/java

# prepare scala sbt
echo "${CYAN}> Preparing SBT.${ENDC}"
echo "deb https://dl.bintray.com/sbt/debian /" | sudo tee /etc/apt/sources.list.d/sbt.list > /dev/null
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 642AC823
echo ""

# install java, [rabbitmq and] scala
echo "${CYAN}> Updating package indizes.${ENDC}"
sudo apt-get update
echo ""
echo "${CYAN}> Installing Oracle Java 8.${ENDC}"
sudo apt-get install -y oracle-java8-installer
echo ""
# sudo rm -rf /var/cache/oracle-jdk8-installer
# JAVA_HOME=/usr/lib/jvm/java-8-oracle
if [[ $INSTALL_RABBITMQ -eq 1 ]]; then
    echo "${CYAN}> Installing RabbitMQ.${ENDC}"
    sudo apt-get install -y rabbitmq-server
    sudo service rabbitmq-server start
    echo ""
fi

echo "${CYAN}> Installing SBT.${ENDC}"
sudo apt-get install -y sbt
echo ""

info "> Preparing Holmes-Totem."
if [[ -d "$INSTALL_DIRECTORY" && "$(ls -A $INSTALL_DIRECTORY)" ]]; then
    if [[ -f "$INSTALL_DIRECTORY/uninstall.sh" ]]; then
        cd $INSTALL_DIRECTORY
        (uninstall.sh --keep-docker --keep-rabbitmq --remove-data --keep-sbt --keep-java8)
        cd "$START_PWD"
    fi
    sudo rm -rf "$INSTALL_DIRECTORY" &>/dev/null
fi
sudo mkdir -p "$INSTALL_DIRECTORY"
# get sources
if [[ $INSTALL_FROM_WDIR -eq 1 ]]; then
    # use tar for copy
    info "> Copying files from working directory to installation destination."
    sudo su root -c "tar cf - . | (cd \"$INSTALL_DIRECTORY\" && tar xBf -)"
    cd $INSTALL_DIRECTORY
else
    info "> Cloning Holmes-Totem."
    cd $INSTALL_DIRECTORY
    sudo chown $USER:$USER $INSTALL_DIRECTORY
    git clone $INSTALL_REPOSITORY .
fi
# if we cloned the default repo we need to install the example config
cd config
if [[ ! -f "totem.conf" ]]; then
    cp totem.conf.example totem.conf
fi
if [[ ! -f "docker-compose.yml" ]]; then
    cp docker-compose.yml.example docker-compose.yml
fi
cd ..
# build
info "> Building Holmes-Totem."
sudo chown -R totem:totem $INSTALL_DIRECTORY
sudo su totem -c "cd $INSTALL_DIRECTORY && sbt assembly"

# if we detected a supported init syste type, install a service script
if [[ $INSTALL_INIT_SCRIPT -eq 1 ]]; then
    cd "$START_PWD" # change back to the directory we started in, where the installation scripts reside
    if [[ $INIT_SYSTEM = "init" ]]; then
        sudo install/init/upstart.install.sh "$START_PWD" "$INSTALL_DIRECTORY"
    else
        sudo install/init/systemd.install.sh "$START_PWD" "$INSTALL_DIRECTORY"
    fi
    # Finish notice
    echo "${GREEN}"
    echo "> Finished. Totem got successfully installed and is now running as a service on your system!"
    echo "  To start/stop Totem or its services, please use your init systems functionality (initctl or systemctl)."
    echo "  Please note that docker-compose will take some time to build your services."
    echo "${ENDC}"
else
    # Finish notice
    echo "${GREEN}"
    echo "> Finished installing. To launch Holmes-Totem change into totem users context (sudo su totem) and issue the following commands:"
    echo "  cd $INSTALL_DIRECTORY/config"
    echo "  docker-compose up -d"
    echo "  cd .."
    echo "  java -jar ./target/scala-2.11/totem-assembly-1.0.jar ./config/totem.conf"
    echo "${ENDC}"
fi
