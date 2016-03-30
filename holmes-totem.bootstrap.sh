#!/bin/bash
echo ""


# set up global helper functions
function error () {
    >&2 echo $1
}
function clean_sources_list () {
    sudo cat /etc/apt/sources.list | perl -ne '$H{$_}++ or print' > sources.list
    sudo mv sources.list /etc/apt/sources.list
}

# set up global variables
HOLMES_TOTEM_DEFAULT_REPO="https://github.com/HolmesProcessing/Holmes-Totem"
HOLMES_TOTEM_REPOSITORY=""
DEFAULT_INSTALLATION_DIRECTORY="/data/holmes-totem"
INSTALLATION_DIRECTORY=""

# distinguish based on operating system, for now only linux?
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    echo "> Found OSTYPE Linux"
    
    # find out the operating system flavor (Ubuntu/Debian/etc)
    OS=$(lsb_release -si)
    OS_VERSION=$(lsb_release -sr)
    OS_CODENAME=$(lsb_release -sc)
    
    # if it is Ubuntu / Debian, we can offer auto-installation of Docker if the kernel version is sufficient
    if [[ $OS == "Ubuntu" || $OS == "Debian" ]]; then
        echo "> Found OS flavor $OS"
        echo ""
        
        # ----------------------------------------------------------------------
        # gather kernel version
        KERNEL_VERSION=$(uname -r | sed -e 's/-.*//;s/\(.*\)\..*/\1/')
        MAJOR_KERNEL_VERSION=$(echo $KERNEL_VERSION | sed -e 's/\..*//')
        MINOR_KERNEL_VERSION=$(echo $KERNEL_VERSION | sed -e 's/.*\.//')
        
        # ----------------------------------------------------------------------
        # check for docker availability
        INSTALL_IN_DOCKER=0
        DOCKER_EXISTS=0
        DOCKER_VERSION=""
        if [[ $MAJOR_KERNEL_VERSION -lt 3 || $MINOR_KERNEL_VERSION -lt 10 ]]; then
            error "> Your kernel version does not support running Docker, but Holmes-Totem requires Docker."
            error "  If you wish install Holmes-Totem, please first upgrade your kernel (>=3.10)."
            echo ""
            exit 1
        else
            DOCKER_VERSION=$(docker -v)
            if [[ $? -eq 0 ]]; then
                DOCKER_EXISTS=1
                echo "> Detected an existing Docker installation."
            else
                DOCKER_EXISTS=0
                error "> No Docker installation found."
            fi
            echo ""
            
            echo "> Do you wish to install Holmes-Totem into a Docker container? (Discouraged, scaling and automatic setup of services is not supported)"
            options=("Install on host" "Install in Docker container (discouraged)")
            select opt in "${options[@]}"
            do
                case $opt in
                    "Install in Docker container (discouraged)")
                        echo "> Installing Totem-Holmes in a Docker container"
                        INSTALL_IN_DOCKER=1
                        break
                        ;;
                    *)
                        echo "> Installing Totem-Holmes directly on the host"
                        echo ""
                        INSTALL_IN_DOCKER=0
                        
                        echo "> In what directory do you want to install? (default: current directory)"
                        read -e -p "  :> " -i "$DEFAULT_INSTALLATION_DIRECTORY" INSTALLATION_DIRECTORY
                        
                        # check if installation directory exists and warn if it does
                        if [[ -d "$INSTALLATION_DIRECTORY" ]]; then
                            echo ""
                            error "> Selected installation destination isn't empty and will be erased if you choose to continue."
                            sub_options=("Install anyways" "Abort Installation")
                            select subopt in "${sub_options[@]}"
                            do
                                case $subopt in
                                    "Install anyways")
                                        echo "> Removing $INSTALLATION_DIRECTORY."
                                        break
                                        ;;
                                    "Abort Installation")
                                        echo "> Aborting installation."
                                        echo ""
                                        exit 0
                                        ;;
                                esac
                            done
                        fi
                        
                        break
                        ;;
                esac
            done
            echo ""
        fi
        
        # ----------------------------------------------------------------------
        # ask if the user wants to install it from the default or a custom repository
        echo ""
        echo "> Holmes-Totem can be installed in its most basic unconfigured version from the Holmes-Processing github - however, in order to override the defaults with your own settings you should provide your own repository here."
        echo "  Please enter a repository to install from:"
        read -e -p "  :> " -i "$HOLMES_TOTEM_DEFAULT_REPO" HOLMES_TOTEM_REPOSITORY
        echo ""
        
        # ----------------------------------------------------------------------
        # install docker if not already installed, do that now
        if [[ $DOCKER_EXISTS -eq 0 ]]; then
            echo "> Installing Docker."
            
            # add the gpg key for the apt repository
            sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D
            
            # flavor specific treatment
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
        # install in docker if requested by the client
        if [[ $INSTALL_IN_DOCKER -eq 1 ]]; then
            # install inside of a docker container
            echo "> Installing Totem."
            DOCKERFILE=$(cat <<DOCKERFILE
# --------------------------------------- #
# Oracle Java 8 installation taken from
# https://github.com/dockerfile/java
# https://github.com/dockerfile/java/tree/master/oracle-java8

FROM ubuntu
RUN apt-get install -y software-properties-common
RUN \
    echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | debconf-set-selections && \
    add-apt-repository -y ppa:webupd8team/java && \
    apt-get update && \
    apt-get install -y oracle-java8-installer && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/oracle-jdk8-installer
ENV JAVA_HOME /usr/lib/jvm/java-8-oracle

# --------------------------------------- #
# enable https for apt
RUN apt-get update && apt-get install -y apt-transport-https

# install rabbitmq
RUN echo "deb http://www.rabbitmq.com/debian/ testing main" | tee -a /etc/apt/sources.list.d/rabbitmq.list
RUN wget https://www.rabbitmq.com/rabbitmq-signing-key-public.asc
RUN apt-key add rabbitmq-signing-key-public.asc
RUN apt-get update && apt-get install -y rabbitmq-server

# install scala sbt
RUN echo "deb https://dl.bintray.com/sbt/debian /" | tee -a /etc/apt/sources.list.d/sbt.list
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 642AC823
RUN apt-get update
RUN apt-get install -y sbt

# setup Holmes-Totem
RUN apt-get install -y git
RUN mkdir -p /data
WORKDIR /data
RUN git clone HOLMES_TOTEM_REPOSITORY
WORKDIR /data/Holmes-Totem
RUN sbt assembly

# start totem
CMD service rabbitmq-server start && java -jar /data/Holmes-Totem/target/scala-2.11/totem-assembly-1.0.jar /data/Holmes-Totem/config/totem.conf

DOCKERFILE
)
            DOCKERFILE=$(echo "$DOCKERFILE" | sed -e 's~HOLMES_TOTEM_REPOSITORY~'$HOLMES_TOTEM_REPOSITORY'~')
            echo "$DOCKERFILE" > "Holmes-Totem.dockerfile"
            sudo docker pull dockerfile/java
            sudo docker build -t holmes_totem -f "Holmes-Totem.dockerfile" .
            rm "Holmes-Totem.dockerfile"
            echo ""
            
        else
            # ------------------------------------------------------------------
            # install on the host instead
            
            # create installation directory
            sudo rm -rf "$INSTALLATION_DIRECTORY"
            sudo mkdir -p "$INSTALLATION_DIRECTORY"
            clean_sources_lists
            
            # update existing infrastructure and add required dependencies
            # enable https for apt
            sudo apt-get update
            echo "> Installing base infrastructure dependencies."
            sudo apt-get install -y build-essential python-dev python-pip git apt-transport-https
            echo ""
            
            # create and update Docker user
            if id -u "totem" >/dev/null 2>&1; then
                error "> User 'totem' already exists, re-using it."
            else
                echo "> Creating user 'totem'."
                sudo useradd totem
            fi
            echo "> Assigning user 'totem' to the 'docker' group."
            sudo usermod -aG docker totem
            echo ""
            
            # install java 8
            echo "> Installing Java 8."
            sudo apt-get install -y software-properties-common
            echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | debconf-set-selections
            sudo add-apt-repository -y ppa:webupd8team/java
            sudo apt-get update
            sudo apt-get install -y oracle-java8-installer
            # sudo rm -rf /var/cache/oracle-jdk8-installer
            # JAVA_HOME=/usr/lib/jvm/java-8-oracle
            echo ""
            
            # install rabbitmq
            echo "> Installing RabbitMQ."
            echo "deb http://www.rabbitmq.com/debian/ testing main" > /etc/apt/sources.list.d/rabbitmq.list
            wget https://www.rabbitmq.com/rabbitmq-signing-key-public.asc
            sudo apt-key add rabbitmq-signing-key-public.asc
            sudo apt-get update 
            sudo apt-get install -y rabbitmq-server
            rm rabbitmq-signing-key-public.asc
            sudo service rabbitmq-server start
            echo ""
            
            # install scala sbt
            echo "> Installing SBT."
            echo "deb https://dl.bintray.com/sbt/debian /" > /etc/apt/sources.list.d/sbt.list
            sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 642AC823
            sudo apt-get update
            sudo apt-get install -y sbt
            echo ""
            
            # setup Holmes-Totem
            echo "> Installing Holmes-Totem."
            sudo mkdir -p $INSTALLATION_DIRECTORY
            sudo chown -R $USER:$USER $INSTALLATION_DIRECTORY
            cd $INSTALLATION_DIRECTORY
            git clone $HOLMES_TOTEM_REPOSITORY .
            sbt assembly
            sudo chown -R totem:totem $INSTALLATION_DIRECTORY
            echo ""
            
            # start totem
            echo "> Finished installing. To launch Holmes-Totem change into totem users context (sudo su totem) and issue the following commands:"
            echo "  cd $INSTALLATION_DIRECTORY"
            echo "  docker-compose up -d"
            echo "  cd .."
            echo "  java -jar ./target/scala-2.11/totem-assembly-1.0.jar ./config/totem.conf"
            echo ""
            
        fi
        
        # end ubuntu/debian
        
    fi
    
    # end linux
    
fi

echo ""
