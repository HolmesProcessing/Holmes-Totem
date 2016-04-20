#!/bin/bash

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

#-#-#-#-#-#
# Get command line options
#
declare -A OPT=()
OPT[path]="/data/holmes-totem"
OPT[repository]="cwd"
OPT[erase]=
OPT[initscripts]=1
OPT[services]=1
#
function display_options {
    error "Holmes-Totem Installation script"
    if [[ $# -gt 0 ]]; then
        if [[ $opt != "--help" && $opt != "-h" ]]; then
            error ""
            error "Invalid option '$opt'."
        fi
    fi
    error ""
    error "--path | -p        PATH          : Install Totem in the location specified by 'PATH' (defaults to /data/holmes-totem)"
    error "--repository | -r  REPOSITORY    : Url for the repository to clone (Git) (defaults to special value 'cwd')"
    error "--erase | -e                     : Purge any previous installation in location 'PATH'"
    error "--no-initscripts | -I            : Do not install init scripts"
    error "--no-services | -S               : Do not install totems service init scripts (implied by no-initscripts)"
    error ""
    exit 0
    ;;
}
#
if [ $# -eq 0 ]; then
    display_options
fi
while [ $# -gt 0 ]
do                   
    opt="$1"
    shift
    case "$opt" in
        
        "--repository" | "-r")
            OPT[repository]=$1
            shift
            ;;
        
        "--path" | "-p")
            OPT[path]=$1
            shift
            ;;
        
        "--erase" | "-e")
            OPT[erase]=1
            ;;
        
        "--no-initscripts" | "-I")
            OPT[initscripts]=
            ;;
        
        "--no-services" | "-S")
            OPT[services]=
            ;;
        
        *)
            display_options "$opt"
    esac
done


LOG_FILE="$(pwd)/totem-install.log"
echo "" | tee "$LOG_FILE"
exec > >(tee -a ${LOG_FILE} )
exec 2> >(tee -a ${LOG_FILE} >&2)

echo ""

# set globals and further OPTS
WORKING_DIRECTORY=$(pwd) # remember starting directory

# distinguish based on operating system, for now only linux?
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    info "> Found OSTYPE Linux"
    
    # find out the operating system flavor (Ubuntu/Debian/etc)
    # if lsb_release is not installed, ask the user for a little help
    cmd=""
    if command -v lsb_release >/dev/null 2>&1; then
        cmd="lsb_release"
    else
        if [[ -f /etc/lsb-release || -f /etc/debian_release || -f /etc/debian_version ]]; then
            sudo apt-get install -y lsb-release
            if !command -v lsb_release >/dev/null 2>&1; then
                error "> Installation of lsb_release failed (sudo apt-get install lsb-release)"
                exit 1
            fi
            cmd="lsb_release"
        else
            error "> Your system seems to be unsupported. If you have a Debian or Ubuntu but still get this message, please manually install the package lsb-release."
            exit 1
        fi
    fi
    
    OS=$($cmd -si)
    OS_VERSION=$($cmd -sr)
    OS_CODENAME=$($cmd -sc)
    
    if [[ $OS == "Ubuntu" || $OS == "Debian" ]]; then
        info "> Found OS flavor $OS"
        
        # ----------------------------------------------------------------------
        # if erase not selected, check if destination path is empty
        #
        if [[ "${OPT[path]}" != "$WORKING_DIRECTORY" ]] &&
           [[ ! ${OPT[erase]} ]] &&
           [[ -d "${OPT[path]}" && "$(ls -A ${OPT[path]})" ]]; then
            
            error "> Fatal: destination path exists and is not empty"
            exit 1
        else
            if [[ "${OPT[path]}" != "$WORKING_DIRECTORY" ]] &&
               [[ -d "${OPT[path]}" && "$(ls -A ${OPT[path]})" ]]; then
                
                . install/totem/uninstall_old.sh
            fi
        fi
        
        # ----------------------------------------------------------------------
        # gather kernel version
        #
        KERNEL_VERSION=$(uname -r | sed -e 's/-.*//;s/\(.*\)\..*/\1/')
        KERNEL_VERSION_MAJOR=$(echo $KERNEL_VERSION | sed -e 's/\..*//')
        KERNEL_VERSION_MINOR=$(echo $KERNEL_VERSION | sed -e 's/.*\.//')
        
        # ----------------------------------------------------------------------
        # grab init system
        #
        INIT_SYSTEM=$(cat /proc/1/comm)
        if [[ $INSTALL_INIT_SCRIPT -eq 1 ]]; then
            if [[ $INIT_SYSTEM != "systemd" && $INIT_SYSTEM != "init" ]]; then
                info "> Unknown INIT system (neither systemd, nor init compatible, but rather reporting '$INIT_SYSTEM')."
                INSTALL_INIT_SCRIPT=0
            else
                info "> Init system is $INIT_SYSTEM"
            fi
        fi
        
        # ----------------------------------------------------------------------
        # create user if not exists
        #
        if id -u "totem" >/dev/null 2>&1; then
            info "> User 'totem' already exists, re-using it."
        else
            info "> Creating user 'totem'."
            sudo useradd totem
            # just useradd is not enough, sbt will crash because it can't
            # create its cash in ~/.sbt
            sudo /sbin/mkhomedir_helper totem
        fi
        info ""
        
        # ----------------------------------------------------------------------
        # if services selected for installation, install Docker if not present
        #
        if [ ${OPT[services]} ]; then
            . install/services/install_services.sh
        fi
        
        # run sub-installer
        # must be sourced to pass the required variables
        . install/totem/install_totem.sh
        
        # end ubuntu/debian
    
    else
        
        error "> Unsupported Linux distribution."
        
    fi
    
    # end linux

else
    
    error "> Unsupported OS type. (Non-Linux)"
    
fi

echo ""
