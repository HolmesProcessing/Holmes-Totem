#!/bin/bash
LOG_FILE="$(pwd)/totem-install.log"
exec > >(tee -a ${LOG_FILE} )
exec 2> >(tee -a ${LOG_FILE} >&2)

echo ""
START_PWD=$(pwd) # remember starting directory

# set up global helper functions
function error () {
    >&2 echo $1
}
function tolower () {
    x=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    echo $x
}

# font colors
# check for interactive shell
if [[ $- == *i* ]]
then
    RED=$(tput setaf 1) #red
    GREEN=$(tput setaf 2) #green
    MAGENTA=$(tput setaf 5) #magenta
    CYAN=$(tput setaf 6) #cyan
    ENDC=$(tput sgr0)   #ends color
else
    RED=''
    GREEN=''
    MAGENTA=''
    CYAN=''
    ENDC=''
fi

# set up global variables
HOLMES_TOTEM_DEFAULT_REPOSITORY="https://github.com/HolmesProcessing/Holmes-Totem"

# distinguish based on operating system, for now only linux?
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    echo "${CYAN}> Found OSTYPE Linux${ENDC}"
    
    # find out the operating system flavor (Ubuntu/Debian/etc)
    # if lsb_release is not installed, ask the user for a little help
    null=$(which lsb_release)
    if [[ $? -ne 0 ]]; then
        error "${RED}> Fatal: lsb_release not installed but required.${ENDC}"
        if [[ -d /etc/lsb-release || -d /etc/debian_release || -d /etc/debian_version ]]; then
            error "${RED}> System could be Debian/Ubuntu.${ENDC}"
            read -e -p "${MAGENTA}> In order to continue, lsb_release needs to be installed, do you want to do that now? (Y/n): ${ENDC}" INPUT
            INPUT=$(tolower $INPUT)
            if [[ $INPUT == "y" || $INPUT == "yes" || $INPUT == "" ]]; then
                echo "${CYAN}> Installing lsb-release package.${ENDC}"
                apt-get install lsb-release
            else
                error "${RED}> Installation aborted.${ENDC}"
                exit 1
            fi
        else
            error "${RED}> Operating system could not be recognized. Aborting installation.${ENDC}"
            exit 1
        fi
    fi
    
    OS=$(lsb_release -si)
    OS_VERSION=$(lsb_release -sr)
    OS_CODENAME=$(lsb_release -sc)
    
    # if it is Ubuntu / Debian, we can offer auto-installation of Docker if the kernel version is sufficient
    if [[ $OS == "Ubuntu" || $OS == "Debian" ]]; then
        echo "${CYAN}> Found OS flavor $OS${ENDC}"
        
        # ----------------------------------------------------------------------
        # gather kernel version
        #
        KERNEL_VERSION=$(uname -r | sed -e 's/-.*//;s/\(.*\)\..*/\1/')
        KERNEL_VERSION_MAJOR=$(echo $KERNEL_VERSION | sed -e 's/\..*//')
        KERNEL_VERSION_MINOR=$(echo $KERNEL_VERSION | sed -e 's/.*\.//')
        
        
        # ----------------------------------------------------------------------
        # grab init system
        INIT_SYSTEM=$(cat /proc/1/comm)
        INSTALL_INIT_SCRIPT=0
        if [[ $INIT_SYSTEM != "systemd" && $INIT_SYSTEM != "init" ]]; then
            error "${RED}> UNKNOWN INIT SYSTEM (neither systemd, nor init compatible, but rather reporting '$INIT_SYSTEM')${ENDC}"
            INSTALL_INIT_SCRIPT=-1
        else
            echo "${CYAN}> Init system is $INIT_SYSTEM${ENDC}"
        fi
        
        
        # ----------------------------------------------------------------------
        # check for docker availability
        #
        DOCKER_IS_INSTALLED=0
        DOCKER_VERSION=""
        #
        if [[ $KERNEL_VERSION_MAJOR -lt 3 ]] || [[ $KERNEL_VERSION_MAJOR -eq 3 && $KERNEL_VERSION_MINOR -lt 10 ]]; then
            error "${RED}> Your kernel version does not support running Docker, but Holmes-Totem requires Docker."
            error "  If you wish install Holmes-Totem, please first upgrade your kernel (>=3.10).${ENDC}"
            echo ""
            exit 1
        else
            DOCKER_VERSION=$(docker -v)
            if [[ $? -eq 0 ]]; then
                DOCKER_IS_INSTALLED=1
                echo "${CYAN}> Detected an existing Docker installation.${ENDC}"
            else
                error "${RED}> No Docker installation found.${ENDC}"
            fi
            echo ""
        fi
        
        
        # ----------------------------------------------------------------------
        # check if we are in a git repository
        #
        WDIR_IS_GIT_REPOSITORY=0
        if [[ -d ".git" ]]; then
            WDIR_IS_GIT_REPOSITORY=1
        fi
        
        
        # ----------------------------------------------------------------------
        # User and command line options
        #
        
        #-#-#-#-#-#
        # Get command line options
        #
        OPT_INSTALL_IN_DOCKER=-1
        OPT_INSTALL_REPOSITORY=""
        OPT_INSTALL_FROM_CWD=-1
        OPT_INSTALL_PATH=""
        OPT_INSTALL_RABBIT_MQ=-1
        OPT_ERASE_OLD=0
        #
        while [ $# -gt 0 ]
        do                   
            opt=$1
            shift
            case "$opt" in
                "--docker")
                    OPT_INSTALL_IN_DOCKER=1
                    ;;
                "--no-docker")
                    OPT_INSTALL_IN_DOCKER=0
                    ;;
                
                "--repository" | "-r")
                    OPT_INSTALL_REPOSITORY=$1
                    shift
                    ;;
                "--install-from-cwd")
                    OPT_INSTALL_FROM_CWD=1
                    ;;
                "--no-install-from-cwd")
                    OPT_INSTALL_FROM_CWD=0
                    ;;
                
                "--path" | "-p")
                    OPT_INSTALL_PATH=$1
                    shift
                    ;;
                
                "--rabbit-mq")
                    OPT_INSTALL_RABBIT_MQ=1
                    ;;
                "--no-rabbit-mq")
                    OPT_INSTALL_RABBIT_MQ=0
                    ;;
                
                "--erase-old")
                    OPT_ERASE_OLD=1
                    ;;
                "--no-erase-old")
                    OPT_ERASE_OLD=0
                    ;;
                
                "--install-init-script")
                    OPT_INSTALL_INIT_SCRIPT=1
                    ;;
                "--no-install-init-script")
                    OPT_INSTALL_INIT_SCRIPT=0
                    ;;
                
                *)
                    ;;
            esac
        done
        
        #-#-#-#-#-#
        # 1) Install in Container?
        #
        INSTALL_IN_DOCKER=0
        #
        if [[ OPT_INSTALL_IN_DOCKER -eq -1 ]]; then
            read -e -p "${MAGENTA}> Install Holmes-Totem inside of a Docker container? --NOT recommended-- (y/N): ${ENDC}" INPUT
            INPUT=$(tolower $INPUT)
            if [[ $INPUT == "y" || $INPUT == "yes" ]]; then
                echo "${RED}  - Installing in a container.${ENDC}"
                INSTALL_IN_DOCKER=1
            else
                echo "${MAGENTA}  - Installing on the host.${ENDC}"
            fi
        else
            INSTALL_IN_DOCKER=$OPT_INSTALL_IN_DOCKER
        fi
        
        #-#-#-#-#-#
        # 2) Determine repository
        #
        INSTALL_FROM_WDIR=0
        INSTALL_REPOSITORY=""
        #
        if [[ $OPT_INSTALL_REPOSITORY == "" ]]; then
            if [[ $WDIR_IS_GIT_REPOSITORY -eq 1 && $INSTALL_IN_DOCKER -eq 0 && $OPT_INSTALL_FROM_CWD -eq -1 ]]; then
                echo "${MAGENTA}> You seem to be in a git repository already."
                read -e -p "> Do you want to use this repository as the installation base? (Y/n): ${ENDC}" INPUT
                INPUT=$(tolower $INPUT)
                if [[ $INPUT == "y" || $INPUT == "yes" ]]; then
                    INSTALL_FROM_WDIR=1
                fi
            fi
            if [[ $OPT_INSTALL_FROM_CWD -ne -1 ]]; then
                INSTALL_FROM_WDIR=$OPT_INSTALL_FROM_CWD
            fi
            if [[ $INSTALL_FROM_WDIR -eq 0 ]]; then
                read -e -p "${MAGENTA}> Please enter a repository to install from (default: $HOLMES_TOTEM_DEFAULT_REPOSITORY): ${ENDC}" INPUT
                # -i "$HOLMES_TOTEM_DEFAULT_REPOSITORY"
                if [[ $INPUT == "" ]]; then
                    INSTALL_REPOSITORY=$HOLMES_TOTEM_DEFAULT_REPOSITORY
                else
                    INSTALL_REPOSITORY=$INPUT
                fi
            fi
        else
            INSTALL_REPOSITORY=$OPT_INSTALL_REPOSITORY
        fi
        
        #-#-#-#-#-#
        # 3) If not in a container and not in a repo clone, where to install to?
        #
        INSTALL_DIRECTORY_DEFAULT="/data/holmes-totem"
        INSTALL_DIRECTORY=""
        #
        if [[ $OPT_INSTALL_PATH == "" ]]; then
            if [[ $INSTALL_IN_DOCKER -eq 0 && $INSTALL_FROM_WDIR -eq 0 ]]; then
                read -e -p "${MAGENTA}> Where to install Holmes-Totem to? (default: $INSTALL_DIRECTORY_DEFAULT): ${ENDC}" INPUT
                # -i "$INSTALL_DIRECTORY_DEFAULT"
                if [[ $INPUT == "" ]]; then
                    INSTALL_DIRECTORY=$INSTALL_DIRECTORY_DEFAULT
                else
                    INSTALL_DIRECTORY=$INPUT
                fi
            fi
        else
            INSTALL_DIRECTORY=$OPT_INSTALL_PATH
        fi
        # check if installation directory exists and warn if it does
        if [[ -d "$INSTALL_DIRECTORY" && OPT_ERASE_OLD -eq 0 ]]; then
            error "${RED}> The selected installation destination isn't empty.${ENDC}"
            read -e -p "${MAGENTA}> Erase folder? (y/N): ${ENDC}" INPUT
            INPUT=$(tolower $INPUT)
            if [[ $INPUT == "y" || $INPUT == "yes" ]]; then
                echo "${RED}> Erasing $INSTALL_DIRECTORY.${ENDC}"
            else
                echo "${RED}> Aborting installation.${ENDC}"
                exit 0
            fi
        fi
        
        #-#-#-#-#-#
        # 4) Install RabbitMQ as well?
        #
        INSTALL_RABBITMQ=0
        #
        if [[ $OPT_INSTALL_RABBIT_MQ -eq -1 ]]; then
            read -e -p "${MAGENTA}> Do you want to install RabbitMQ as well? (y/N): ${ENDC}" INPUT
            INPUT=$(tolower $INPUT)
            if [[ INPUT == "y" || INPUT == "yes" ]]; then
                INSTALL_RABBITMQ=1
            fi
        else
            INSTALL_RABBITMQ=$OPT_INSTALL_RABBIT_MQ
        fi
        
        #-#-#-#-#-#
        # 5) Install service scripts? (supported init systems: upstart/systemd)
        #
        # INSTALL_INIT_SCRIPT
        #
        if [[ INSTALL_INIT_SCRIPT -ne -1 ]]; then
            if [[ $OPT_INSTALL_INIT_SCRIPT -eq -1 ]]; then
                read -e -p "${MAGENTA}> Your system is upstart or systemd compatible. Do you want to install Totem as a service? (Y/n): ${ENDC}" INPUT
                INPUT=$(tolower $INPUT)
                if [[ INPUT == "y" || INPUT == "yes" ]]; then
                    INSTALL_INIT_SCRIPT=1
                fi
            else
                INSTALL_INIT_SCRIPT=$OPT_INSTALL_INIT_SCRIPT
            fi
        fi
        
        
        echo ""
        
        
        # ----------------------------------------------------------------------
        # Install docker if not already installed, do that now
        #
        if [[ $DOCKER_IS_INSTALLED -eq 0 ]]; then
            echo "${CYAN}> Installing Docker.${ENDC}"
            sudo install/docker/install_docker.sh "$OS" "$OS_CODENAME"
            echo ""
        fi
        
        
        # ----------------------------------------------------------------------
        # Install Totem
        #
        if [[ $INSTALL_IN_DOCKER -eq 1 ]]; then
            echo "${CYAN}> Installing Totem.${ENDC}"
            sudo install/totem/install_in_docker.sh "$INSTALL_REPOSITORY"
            echo ""
            
        else
            # run sub-installer
            # must be sourced to pass the required variables
            . install/totem/install_on_host.sh
        fi
        
        # end ubuntu/debian
        
    fi
    
    # end linux
    
fi

echo ""
