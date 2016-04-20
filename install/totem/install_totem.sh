#!/bin/bash

function install_prerequisites {
    # update existing infrastructure and add required dependencies
    # enable https for apt
    info "> Installing base infrastructure dependencies."
    sudo apt-get update
    sudo apt-get install -y build-essential python-dev python-pip git apt-transport-https software-properties-common
    info ""
}

function install_java8 {
    info "> Installing Oracle Java 8."
    echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | sudo debconf-set-selections
    sudo add-apt-repository -y ppa:webupd8team/java
    sudo apt-get update
    sudo apt-get install -y oracle-java8-installer
    # sudo rm -rf /var/cache/oracle-jdk8-installer
    # JAVA_HOME=/usr/lib/jvm/java-8-oracle
    info ""
}

function install_sbt {
    info "> Installing SBT."
    echo "deb https://dl.bintray.com/sbt/debian /" | sudo tee /etc/apt/sources.list.d/sbt.list > /dev/null
    sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 642AC823
    sudo apt-get update
    sudo apt-get install -y sbt
    info ""
}

function install_totem {
    info "> Preparing Holmes-Totem."
    sudo mkdir -p "${OPT[path]}"
    
    # copy if required
    if [[ "${OPT[path]}" != "$WORKING_DIRECTORY" ]]; then
        if [[ "${OPT[repo]}" = "cwd" ]]; then
            info "> Copying files from working directory to installation destination."
            sudo su root -c "tar cf - . | (cd \"${OPT[path]}\" && tar xBf -)"
            sudo chown -R $USER:$USER "${OPT[path]}"
        else
            info "> Cloning Holmes-Totem."
            cd "${OPT[path]}"
            sudo chown $USER:$USER .
            git clone "${OPT[repo]}" .
        fi
    fi
    
    # check if config exists
    cd "${OPT[path]}/config"
    if [[ ! -f "totem.conf" ]]; then
        cp totem.conf.example totem.conf
    fi
    if [[ ! -f "docker-compose.yml" && $OPT_INSTALL_SERVICES -eq 1 ]]; then
        cp docker-compose.yml.example docker-compose.yml
    fi
    cd ..
    
    # build
    info "> Building Holmes-Totem."
    sudo chown -R totem:totem .
    sudo su totem -c "cd '${OPT[path]}' && sbt assembly"
    
    # if totem init script should be written do so now
    if [ ${OPT[initscripts]} ]; then
        cd "$WORKING_DIRECTORY"
        . install/init/install_totem.sh
        # Finish notice
        echo "${GREEN}"
        echo "> Finished. Totem got successfully installed and is now running as a service on your system!"
        echo "  To start/stop Totem or its services (if installed), please use your init systems functionality (initctl or systemctl)."
        if [ ${OPT[services]} ]; then
            echo "  Please note that docker-compose will take some time to build your services."
            echo "  Please also note, that all services need to build successfully for the holmes-totem-services service to start up correctly."
        fi
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
}

function copy_log {
    # copy the final version of the log
    sudo cp totem-install.log "$INSTALL_DIRECTORY/totem-install.log"
}

function main {
    install_prerequisites
    install_java8
    install_sbt
    install_totem
    copy_log
}

main
