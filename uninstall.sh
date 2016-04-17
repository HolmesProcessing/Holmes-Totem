#!/bin/bash
echo ""
PWD=$(pwd) # remember starting directory

# set up global helper functions
function error () {
    >&2 echo $1
}
function tolower () {
    x=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    echo $x
}

# font colors
RED=$(tput setaf 1) #red
GREEN=$(tput setaf 2) #green
MAGENTA=$(tput setaf 5) #magenta
CYAN=$(tput setaf 6) #cyan
ENDC=$(tput sgr0)   #ends color

# set up global variables

# distinguish based on operating system, for now only linux?
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    echo "${CYAN}> Found OSTYPE Linux${ENDC}"
    
    # find out the operating system flavor (Ubuntu/Debian/etc)
    OS=$(lsb_release -si)
    OS_VERSION=$(lsb_release -sr)
    OS_CODENAME=$(lsb_release -sc)
    
    # if it is Ubuntu / Debian, we can offer auto-installation of Docker if the kernel version is sufficient
    if [[ $OS == "Ubuntu" || $OS == "Debian" ]]; then
        echo "${CYAN}> Found OS flavor $OS${ENDC}"
        
        # ----------------------------------------------------------------------
        # check for docker availability
        #
        DOCKER_IS_INSTALLED=0
        DOCKER_VERSION=""
        #
        DOCKER_VERSION=$(docker -v >/dev/null)
        if [[ $? -eq 0 ]]; then
            DOCKER_IS_INSTALLED=1
        fi
        
        
        # ----------------------------------------------------------------------
        # grab init system
        INIT_SYSTEM=$(cat /proc/1/comm)
        UNINSTALL_INIT_SCRIPT=1
        if [[ $INIT_SYSTEM != "systemd" && $INIT_SYSTEM != "init" ]]; then
            error "${RED}UNKNOWN INIT SYSTEM (neither systemd, nor init compatible, but rather $INIT_SYSTEM)${ENDC}"
            UNINSTALL_INIT_SCRIPT=0
        else
            echo "${CYAN}> Init system is $INIT_SYSTEM${ENDC}"
        fi
        
        
        # ----------------------------------------------------------------------
        # User and command line options
        #
        OPT_UNINSTALL_DOCKER=-1
        OPT_UNINSTALL_RABBITMQ=-1
        OPT_UNINSTALL_JAVA8=-1
        OPT_UNINSTALL_SBT=-1
        OPT_ERASE=-1
        #
        while [ $# -gt 0 ]
        do                   
            opt=$1
            shift
            case "$opt" in
                "--remove-docker")
                    OPT_UNINSTALL_DOCKER=1
                    ;;
                "--keep-docker")
                    OPT_UNINSTALL_DOCKER=0
                    ;;
                
                "--remove-rabbitmq")
                    OPT_UNINSTALL_RABBITMQ=1
                    ;;
                "--keep-rabbitmq")
                    OPT_UNINSTALL_RABBITMQ=0
                    ;;
                
                "--remove-data")
                    OPT_ERASE=1
                    ;;
                "--keep-data")
                    OPT_ERASE=0
                    ;;
                    
                "--remove-sbt")
                    OPT_UNINSTALL_SBT=1
                    ;;
                "--keep-sbt")
                    OPT_UNINSTALL_SBT=0
                    ;;
                
                "--remove-java8")
                    OPT_UNINSTALL_JAVA8=1
                    ;;
                "--keep-java8")
                    OPT_UNINSTALL_JAVA8=0
                    ;;
                
                *)
                    ;;
            esac
        done
        
        #-#-#-#-#-#
        # OPT_UNINSTALL_DOCKER
        #
        if [[ $OPT_UNINSTALL_DOCKER -eq -1 && $DOCKER_IS_INSTALLED -eq 1 ]]; then
            read -e -p "${MAGENTA}> Remove Docker? (y/N): ${ENDC}" INPUT
            INPUT=$(tolower $INPUT)
            if [[ $INPUT == "y" || $INPUT == "yes" ]]; then
                OPT_UNINSTALL_DOCKER=1
            else
                OPT_UNINSTALL_DOCKER=0
            fi
        fi
        
        #-#-#-#-#-#
        # OPT_UNINSTALL_RABBITMQ
        #
        if [[ $OPT_UNINSTALL_RABBITMQ -eq -1 ]]; then
            read -e -p "${MAGENTA}> Remove RabbitMQ? (y/N): ${ENDC}" INPUT
            INPUT=$(tolower $INPUT)
            if [[ $INPUT == "y" || $INPUT == "yes" ]]; then
                OPT_UNINSTALL_RABBITMQ=1
            else
                OPT_UNINSTALL_RABBITMQ=0
            fi
        fi
        
        #-#-#-#-#-#
        # OPT_UNINSTALL_JAVA8
        #
        if [[ $OPT_UNINSTALL_JAVA8 -eq -1 ]]; then
            read -e -p "${MAGENTA}> Remove Oracle Java 8? (y/N): ${ENDC}" INPUT
            INPUT=$(tolower $INPUT)
            if [[ $INPUT == "y" || $INPUT == "yes" ]]; then
                OPT_UNINSTALL_JAVA8=1
            else
                OPT_UNINSTALL_JAVA8=0
            fi
        fi
        
        #-#-#-#-#-#
        # OPT_UNINSTALL_SBT
        #
        if [[ $OPT_UNINSTALL_SBT -eq -1 ]]; then
            read -e -p "${MAGENTA}> Remove SBT? (y/N): ${ENDC}" INPUT
            INPUT=$(tolower $INPUT)
            if [[ $INPUT == "y" || $INPUT == "yes" ]]; then
                OPT_UNINSTALL_SBT=1
            else
                OPT_UNINSTALL_SBT=0
            fi
        fi
        
        #-#-#-#-#-#
        # OPT_ERASE
        #
        if [[ $OPT_ERASE -eq -1 ]]; then
            read -e -p "${MAGENTA}> Remove all files from the installation location? (Warning, install location assumed to be $(pwd)) (y/N): ${ENDC}" INPUT
            INPUT=$(tolower $INPUT)
            if [[ $INPUT == "y" || $INPUT == "yes" ]]; then
                OPT_ERASE=1
            else
                OPT_ERASE=0
            fi
        fi
        
        echo ""
        
        
            
        #-#-#-#-#-#
        # Now that we're finished getting options, execute what was selected
        #
        if [[ $INIT_SYSTEM = "init" ]]; then
            function service_stop {
                sudo service "$1" stop
            }
            function service_disable {}
            function service_remove {
                sudo rm "/etc/init/$1.conf"
            }
            function init_reload {
                sudo initctl reload-configuration
            }
        else
            if [[ $INIT_SYSTEM = "systemd" ]]; then
                function service_stop {
                    sudo systemctl stop "$1"
                }
                function service_disable {
                    sudo systemctl disable "$1"
                }
                function service_remove {
                    sudo rm "/etc/systemd/system/$1.service"
                }
                function init_reload {}
            else
                function service_stop {}
                function service_disable {}
                function service_remove {}
                function init_reload {}
            fi
        fi
        
        if [[ $OPT_UNINSTALL_DOCKER -eq 1 && $DOCKER_IS_INSTALLED -eq 1 ]]; then
            service_stop docker
            sudo apt-get purge -y --auto-remove docker-engine
        fi
        
        if [[ $OPT_UNINSTALL_RABBITMQ -eq 1 ]]; then
            service_stop rabbitmq-server
            sudo apt-get purge -y --auto-remove rabbitmq-server
        fi
        
        if [[ $OPT_UNINSTALL_JAVA8 -eq 1 ]]; then
            sudo apt-get purge -y --auto-remove oracle-java8-installer
        fi
        
        if [[ $OPT_UNINSTALL_SBT -eq 1 ]]; then
            sudo apt-get purge -y --auto-remove sbt
        fi
        
        if [[ $OPT_ERASE -eq 1 ]]; then
            sudo rm -rf $(pwd)/*
        fi
        
        # the following functions only execute if valid init scripts and system
        # have been found
        service_stop holmes-totem-service
        service_stop holmes-totem
        service_disable holmes-totem-service
        service_disable holmes-totem
        service_remove holmes-totem-service
        service_remove holmes-totem
        init_reload
        
        
        # Finish notice
        echo "${GREEN}"
        echo "> Done."
        echo "${ENDC}"
        
        # end ubuntu/debian
        
    fi
    
    # end linux
    
fi

echo ""
