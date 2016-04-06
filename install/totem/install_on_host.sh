#!/bin/bash

# update existing infrastructure and add required dependencies
# enable https for apt
sudo apt-get update
echo ""
echo "${CYAN}> Installing base infrastructure dependencies.${ENDC}"
sudo apt-get install -y build-essential python-dev python-pip git apt-transport-https
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
sudo apt-get install -y software-properties-common
echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | debconf-set-selections
sudo add-apt-repository -y ppa:webupd8team/java

# prepare rabbitmq
if [[ $INSTALL_RABBITMQ -eq 1 ]]; then
    echo "${CYAN}> Preparing RabbitMQ.${ENDC}"
    echo "deb http://www.rabbitmq.com/debian/ testing main" > /etc/apt/sources.list.d/rabbitmq.list
    wget https://www.rabbitmq.com/rabbitmq-signing-key-public.asc
    sudo apt-key add rabbitmq-signing-key-public.asc
    rm rabbitmq-signing-key-public.asc
fi

# prepare scala sbt
echo "${CYAN}> Preparing SBT.${ENDC}"
echo "deb https://dl.bintray.com/sbt/debian /" > /etc/apt/sources.list.d/sbt.list
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

# no cloning, instead take the current directory as the source
if [[ $INSTALL_FROM_WDIR -eq 1 ]]; then
    echo "${CYAN}> Building Holmes-Totem.${ENDC}"
    sudo chown -R totem:totem "."
    sudo su totem -c "sbt assembly"
else
    # setup Holmes-Totem
    echo "${CYAN}> Installing Holmes-Totem.${ENDC}"
    # clean installation directory
    sudo rm -rf "$INSTALL_DIRECTORY"
    sudo mkdir -p "$INSTALL_DIRECTORY"
    sudo chown $USER:$USER $INSTALL_DIRECTORY
    # clone
    cd $INSTALL_DIRECTORY
    git clone $INSTALL_REPOSITORY .
    # if we cloned the default repo we need to install the example config
    if [[ "$INSTALL_DIRECTORY" = "$INSTALL_DIRECTORY_DEFAULT" ]]; then
        cd config
        cp totem.conf.example totem.conf
        cp docker-compose.yml.example docker-compose.yml
        cd ..
    fi
    # build
    sudo chown -R totem:totem $INSTALL_DIRECTORY
    sudo su totem -c "cd $INSTALL_DIRECTORY && ls -al && pwd && sbt assembly"
fi

# if the user wants totem to be installed as a service (upstart/systemd) install the required scripts
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
