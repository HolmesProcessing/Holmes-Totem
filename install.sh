#!/bin/bash
echo ""


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
HOLMES_TOTEM_DEFAULT_REPOSITORY="https://github.com/HolmesProcessing/Holmes-Totem"

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
        # gather kernel version
        #
        KERNEL_VERSION=$(uname -r | sed -e 's/-.*//;s/\(.*\)\..*/\1/')
        KERNEL_VERSION_MAJOR=$(echo $KERNEL_VERSION | sed -e 's/\..*//')
        KERNEL_VERSION_MINOR=$(echo $KERNEL_VERSION | sed -e 's/.*\.//')
        
        
        # ----------------------------------------------------------------------
        # check for docker availability
        #
        DOCKER_IS_INSTALLED=0
        DOCKER_VERSION=""
        #
        if [[ $KERNEL_VERSION_MAJOR -lt 3 || $KERNEL_VERSION_MINOR -lt 10 ]]; then
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
        
        
        echo ""
        
        
        # ----------------------------------------------------------------------
        # Install docker if not already installed, do that now
        #
        if [[ $DOCKER_IS_INSTALLED -eq 0 ]]; then
            echo "${CYAN}> Installing Docker.${ENDC}"
            
            # Add the gpg key for the apt repository
            sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
            
            # Flavor specific treatment
            if [[ $OS == "Ubuntu" ]]; then
                sudo echo "deb https://apt.dockerproject.org/repo ubuntu-$OS_CODENAME main" > /etc/apt/sources.list.d/docker.list
                sudo apt-get update && sudo apt-get purge lxc-docker
            else
                sudo echo "deb https://apt.dockerproject.org/repo debian-$OS_CODENAME main" > /etc/apt/sources.list.d/docker.list
                sudo apt-get update && sudo apt-get purge lxc-docker* docker.io*
            fi
            
            # Install Docker, this requires the linux image extra as well
            sudo apt-get install -y linux-image-extra-$(uname -r)
            sudo apt-cache policy docker-engine
            sudo apt-get install -y docker-engine
            
            # Install Docker Compose
            sudo pip install docker-compose
            
            # Start Docker daemon
            sudo service docker start
            echo ""
        fi
        
        
        # ----------------------------------------------------------------------
        # Install Totem
        #
        if [[ $INSTALL_IN_DOCKER -eq 1 ]]; then
            # ------------------------------------------------------------------
            # Install inside of a docker container
            #
            echo "${CYAN}> Installing Totem.${ENDC}"
            DOCKERFILE=$(cat Docker/Install.dockerfile)
            DOCKERFILE=$(echo "$DOCKERFILE" | sed -e 's~INSTALL_REPOSITORY~'$INSTALL_REPOSITORY'~')
            echo "$DOCKERFILE" > "Install.dockerfile.modified"
            sudo docker build -t holmes_totem -f "Install.dockerfile.modified" .
            rm "Install.dockerfile.modified"
            echo ""
            
        else
            # ------------------------------------------------------------------
            # install on the host instead
            #
            
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
            
            # install scala sbt
            echo "${CYAN}> Preparing SBT.${ENDC}"
            echo "deb https://dl.bintray.com/sbt/debian /" > /etc/apt/sources.list.d/sbt.list
            sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 642AC823
            echo ""
            
            
            
            # run installations
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
                # build
                sudo chown -R totem:totem $INSTALL_DIRECTORY
                sudo su totem -c "cd $INSTALL_DIRECTORY && ls -al && pwd && sbt assembly"
            fi
            
            
            
            # Finish notice
            echo "${GREEN}"
            echo "> Finished installing. To launch Holmes-Totem change into totem users context (sudo su totem) and issue the following commands:"
            echo "  cd $INSTALL_DIRECTORY/config"
            echo "  docker-compose up -d"
            echo "  cd .."
            echo "  java -jar ./target/scala-2.11/totem-assembly-1.0.jar ./config/totem.conf"
            echo "${ENDC}"
            
            # end host install
            
        fi
        
        # end ubuntu/debian
        
    fi
    
    # end linux
    
fi

echo ""
