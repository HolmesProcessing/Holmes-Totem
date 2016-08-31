# Holmes-Totem: A Holmes Processing Investigation Planner for Large-scale File Analysis [![Build Status](https://travis-ci.org/HolmesProcessing/Holmes-Totem.svg?branch=master)](https://travis-ci.org/HolmesProcessing/Holmes-Totem)

## Overview
The Holmes-TOTEM Planner is responsible for turning data into information by performing feature extraction against submitted objects. When tasked, Holmes-TOTEM schedules the execution of its services which are capable of performing static and dynamic analysis as well as gather data from third parties.

The Holmes-TOTEM Investigation Planner is optimized for executing extraction services that complete in a few seconds, i.e. static analysis and 3rd party queries. When dealing with services that take longer to complete, we recommend pairing the Holmes-TOTEM Planner with [Holmes-TOTEM-Long](https://github.com/HolmesProcessing/Holmes-Totem-Long).

## Dependencies
Holmes-TOTEM is built with the [Akka Toolkit](http://akka.io/) and performs best with [Oracle's Java 8](https://docs.oracle.com/javase/8/docs/technotes/guides/install/install_overview.html). When executing tasks, Holmes-TOTEM requires an HTTP complaint server for delivering files, a database for storing results, and a queuing server for organizing tasking.

### Compiling and Executing
Holmes-Totem requires [Java 8](https://docs.oracle.com/javase/8/docs/technotes/guides/install/install_overview.html) and we used the [SBT](http://www.scala-sbt.org/) build tool for dependency management and assembling.

### Queuing Server
[RabbitMQ](https://www.rabbitmq.com/) is the queuing server of choice for Holmes Processing. Other AMQP complaint services should work but are untested by Holmes Processing. For sending tasking to the queuing server, we recommend using [Holmes-Gateway](https://github.com/HolmesProcessing/Holmes-Gateway) for optimizing the tasking and handling user authentication. 

### Serving Files and Storing Results
[Holmes-Storage](https://github.com/HolmesProcessing/Holmes-Storage) is the Holmes Processing recommendation for managing the sample repository and storing Holmes-TOTEM results. While not strictly required, Holmes-Storage will ease the creation of the databases and supply the information in the expected format for other Holmes Processing solutions. 

### Using Supplied Services
The supplied services rely on [Docker](https://docs.docker.com/) and [Docker-Compose](https://docs.docker.com/compose/).

## Installation

### Automated
[Holmes-Toolbox](https://github.com/HolmesProcessing/Holmes-Toolbox) provides install scripts for quick installation. 

### Manual
1) Clone the Git Repository and Change Directory
```shell
git clone https://github.com/HolmesProcessing/Holmes-Totem.git
cd Holmes-Totem
```

2) Compile Holmes-TOTEM
Holmes-TOTEM uses SBT to download all dependencies and compile the source into a working JAR file.
```shell
sbt assembly
```
The assembled jar file will be located in `./target/scala-2.11/totem-assembly-1.0.jar`

## Configuration
1) Perform Totem Configuration
Holmes-TOTEM is packaged with sane configuration defaults for Holmes-TOTEM and Docker-Compose. These configuration settings will configure the system to use all available Holmes-TOTEM services. These default configuration can be used by removing the `.example` tag at the end of the file name.
```shell
cp ./config/totem.conf.example ./config/totem.conf
cp ./config/docker-compose.yml.example ./config/docker-compose.yml.example
```
After the files are created, please perform any adjustments to the configuration to match your environment and needs. You will most likely need to adjust the values for `rabbit_settings`.

2) Perform Service Configuration
Holmes-TOTEM provides a number of standard services that are packaged as Docker containers. These containers will manage all dependencies but configuration is still required. In most cases this should be as simple as renaming the `service.conf.example` file to `service.conf`. However, some services will require an API key or additional information to execute. For more information and details on the options available, please visit the directory and read the `README.md` for each service `./src/main/scala/org/holmesprocessing/totem/services/`

## Using Configuration Files From Holmes-Storage
Holmes-TOTEM allows you to upload the configuration files for the individual services to Holmes-Storage. You can upload individual files manually:
```shell
curl -F config=@${confPath} http://${storageIP}:${storagePort}/config/${serviceName}/service.conf
```
or you can use the script to automatically upload all your service.conf-files:
```shell
cd config
./upload_configs.sh ${storageIP}:${storagePath}
```
This script will go through each service and look for the file "service.conf" and upload it. If there is no such file, it will upload the file "service.conf.example", if it exists. Before uploading, the script asks for each file individually, since existing configurations on storage are overwritten.

In order to use these uploaded configuration files, use the script
```shell
cd config
./compose_download_conf.sh ${storageIP}:${storagePath}
```

## Running Holmes-TOTEM
1) Start the Services
```shell
docker-compose -f ./config/docker-compose.yml up -d
```

2) Execute Holmes-TOTEM
```shell
java -jar ./target/scala-2.11/totem-assembly-1.0.jar
```

## Tasking Holmes-TOTEM

### SKALD Tasking (Recommended)
We recommend using [Holmes-Gateway](https://github.com/HolmesProcessing/Holmes-Gateway) for optimizing the tasking and handling user authentication. Please visit the Holmes-Gateway repository for further information.

### Manual Tasking with Holmes-Toolbox
[Holmes-Toolbox](https://github.com/HolmesProcessing/Holmes-Toolbox)  provides a Command Line Interface (CLI) for sending tasking to Holmes-TOTEM.

### Manual Tasking with AMQP
Holmes-TOTEM can be manually tasked using custom created AMQP message using JSON as the message body. The following minimal example will task Holmes-TOTEM to execute PEID, YARA, and PEINFO against a sample. 
```python
SAMPLE = <sample>
URI = "<Storage URL>" + SAMPLE
        jdict = {
                "download": True,     #specifies if TOTEM should download the file
                "primaryURI": URI,    #first URI to download the file
                "secondaryURI": URI,  #back up URI to download the file
                "filename": SAMPLE,   #filename of the sample, or identifier (i.e. domain name) if !download 
                "tasks": {            #list or tasks to execute with optional arguments
                        "PEID": []
                        "YARA": [],
                        "PEINFO": [],
                },
                "tags": [             #add an optional source tag
                        "totem-test"
                ],
                "attempts": 0
        }
```

## Acknowledgment
Holmes-Totem is derived from the Novetta open source project Totem and Holmes Group LLC is not related or endorsed by Novetta. We gracelessly thank Novetta for their contribution and we could not have created this project without their support. 

Holmes Processing would also like to thank the [CRITs](https://crits.github.io/) team for their valuable discussions and support they provided.
