#!/bin/bash
LOG_FILE="$(pwd)/totem-install.log"
echo "" | tee "$LOG_FILE"
exec > >(tee -a ${LOG_FILE} )
exec 2> >(tee -a ${LOG_FILE} >&2)

echo ""
START_PWD=$(pwd) # remember starting directory

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

# set up global helper functions
function error {
    >&2 echo "${RED}$1${ENDC}"
}
function info {
    echo "${CYAN}$1${ENDC}"
}
function tolower {
    x=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    echo $x
}
function readinput {
    read -e -p "${MAGENTA}$1: ${ENDC}" INPUT
    INPUT=$(tolower $INPUT)
    echo "$INPUT"
}

# set up global variables
HOLMES_TOTEM_DEFAULT_REPOSITORY="https://github.com/HolmesProcessing/Holmes-Totem"

# distinguish based on operating system, for now only linux?
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    info "> Found OSTYPE Linux"
    
    # find out the operating system flavor (Ubuntu/Debian/etc)
    # if lsb_release is not installed, ask the user for a little help
    null=$(which lsb_release)
    if [[ $? -ne 0 ]]; then
        info "> Fatal: lsb_release not installed but required."
        if [[ -d /etc/lsb-release || -d /etc/debian_release || -d /etc/debian_version ]]; then
            info "> System could be Debian/Ubuntu."
            INPUT=$(readinput "> In order to continue, lsb_release needs to be installed, do you want to do that now? (Y/n)")
            if [[ $INPUT == "y" || $INPUT == "yes" || $INPUT == "" ]]; then
                info "> Installing lsb-release package."
                apt-get install lsb-release
            else
                error "> Installation aborted."
                exit 1
            fi
        else
            error "> Operating system could not be recognized. Aborting installation."
            exit 1
        fi
    fi
    
    OS=$(lsb_release -si)
    OS_VERSION=$(lsb_release -sr)
    OS_CODENAME=$(lsb_release -sc)
    
    # if it is Ubuntu / Debian, we can offer auto-installation of Docker if the kernel version is sufficient
    if [[ $OS == "Ubuntu" || $OS == "Debian" ]]; then
        info "> Found OS flavor $OS"
        
        # ----------------------------------------------------------------------
        # gather kernel version
        #
        KERNEL_VERSION=$(uname -r | sed -e 's/-.*//;s/\(.*\)\..*/\1/')
        KERNEL_VERSION_MAJOR=$(echo $KERNEL_VERSION | sed -e 's/\..*//')
        KERNEL_VERSION_MINOR=$(echo $KERNEL_VERSION | sed -e 's/.*\.//')
        
        
        # ----------------------------------------------------------------------
        # grab init system
        INIT_SYSTEM=$(cat /proc/1/comm)
        INSTALL_INIT_SCRIPT=1
        if [[ $INIT_SYSTEM != "systemd" && $INIT_SYSTEM != "init" ]]; then
            info "> Unknown INIT system (neither systemd, nor init compatible, but rather reporting '$INIT_SYSTEM')."
            INSTALL_INIT_SCRIPT=0
        else
            info "> Init system is $INIT_SYSTEM"
        fi
        
        
        # ----------------------------------------------------------------------
        # check for docker availability
        #
        DOCKER_IS_INSTALLED=0
        DOCKER_VERSION=""
        #
        if [[ $KERNEL_VERSION_MAJOR -lt 3 ]] || [[ $KERNEL_VERSION_MAJOR -eq 3 && $KERNEL_VERSION_MINOR -lt 10 ]]; then
            error "> Your kernel version does not support running Docker, however Holmes-Totem default installation requires Docker."
            error "  If you wish to install Holmes-Totem with this script, please first upgrade your kernel (>=3.10)."
            exit 1
        else
            DOCKER_VERSION=$(docker -v 2>&1 >/dev/null)
            if [[ $? -eq 0 ]]; then
                DOCKER_IS_INSTALLED=1
                info "> Detected an existing Docker installation."
            else
                info "> No Docker installation found."
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
        OPT_INSTALL_REPOSITORY=""
        OPT_INSTALL_FROM_CWD=-1
        OPT_INSTALL_PATH=""
        # OPT_INSTALL_RABBIT_MQ=-1
        OPT_ERASE_OLD=-1
        #
        while [ $# -gt 0 ]
        do                   
            opt=$1
            shift
            case "$opt" in
                
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
                
                "--install-path" | "-p")
                    OPT_INSTALL_PATH=$1
                    shift
                    ;;
                
                "--erase-old")
                    OPT_ERASE_OLD=1
                    ;;
                "--no-erase-old")
                    OPT_ERASE_OLD=0
                    ;;
                
                "--no-init-script")
                    INSTALL_INIT_SCRIPT=0
                    ;;
                
                *)
                    error "Holmes-Totem Installation script"
                    if [[ $opt != "--help" && $opt != "-h" ]]; then
                        error "Invalid option '$1'."
                    fi
                    error "Valid command line options are:"
                    error "--repository REPOSITORY    : Url for the repository to clone (Git) (incompatible with --install-from-cwd)"
                    error "--install-from-cwd         : Force installation from current directory (incompatible with --install-path and --repository)"
                    error "--no-install-from-cwd      : Ignore current directory if it is a Git repository"
                    error "--install-path PATH        : Use specified path as the directory to install in (incompatible with --install-from-cwd)"
                    error "--erase-old                : Empty the installation directory (incompatible with --install-from-cwd)"
                    error "--no-erase-old             : Do not empty the installation directory, abort if not empty"
                    error "--no-init-script           : Do not install an init script for totem/service automation"
                    exit 0
                    ;;
            esac
        done
        
        #-#-#-#-#-#
        # 1) Determine repository
        #
        INSTALL_FROM_WDIR=0
        INSTALL_REPOSITORY=""
        #
        if [[ $OPT_INSTALL_REPOSITORY == "" ]]; then
            if [[ $WDIR_IS_GIT_REPOSITORY -eq 1 && $OPT_INSTALL_FROM_CWD -eq -1 ]]; then
                info "> Git repository detected in working directory."
                INPUT=$(readinput "> Do you want to use this repository as the installation base? (Y/n)")
                if [[ $INPUT == "" ]]; then
                    INSTALL_FROM_WDIR=1
                fi
            fi
            if [[ $OPT_INSTALL_FROM_CWD -ne -1 ]]; then
                INSTALL_FROM_WDIR=$OPT_INSTALL_FROM_CWD
            fi
            if [[ $INSTALL_FROM_WDIR -eq 0 ]]; then
                INPUT=$(readinput "> Please enter a repository to install from (default: $HOLMES_TOTEM_DEFAULT_REPOSITORY)")
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
        # 2) If not in a container and not in a repo clone, where to install to?
        #
        INSTALL_DIRECTORY_DEFAULT="/data/holmes-totem"
        INSTALL_DIRECTORY=""
        #
        if [[ "$OPT_INSTALL_PATH" = "" ]]; then
            INPUT=$(readinput "> Where do you want to install Holmes-Totem to? (default: $INSTALL_DIRECTORY_DEFAULT)")
            if [[ $INPUT == "" ]]; then
                INSTALL_DIRECTORY=$INSTALL_DIRECTORY_DEFAULT
            else
                INSTALL_DIRECTORY=$INPUT
            fi
        else
            INSTALL_DIRECTORY=$OPT_INSTALL_PATH
        fi
        # check if installation directory exists and warn if it does
        if [[ -d "$INSTALL_DIRECTORY" && "$(ls -A $INSTALL_DIRECTORY)" ]]; then
            if [[ OPT_ERASE_OLD -eq -1 ]]; then
                info "> The selected installation destination isn't empty."
                INPUT=$(readinput "> Erase directory contents? (y/N)")
                if [[ $INPUT == "y" || $INPUT == "yes" ]]; then
                    OPT_ERASE_OLD=1
                else
                    OPT_ERASE_OLD=0
                fi
            fi
            if [[ OPT_ERASE_OLD -eq 1 ]]; then
                info "> Selected to remove the old installation ($INSTALL_DIRECTORY)."
            else
                info "> Selected to keep the old installation. Aborting any further action."
                exit 0
            fi
        fi
        
        
        info ""
        
        
        # ----------------------------------------------------------------------
        #
        if [[ $DOCKER_IS_INSTALLED -eq 0 ]]; then
            . install/docker/install_docker.sh
        fi
        
        # run sub-installer
        # must be sourced to pass the required variables
        . install/totem/install_on_host.sh
        
        # end ubuntu/debian
        
    fi
    
    # end linux
    
fi

echo ""
