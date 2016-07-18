# Holmes-TOTEM: An Investigation Planner for large-scale file analysis [![Build Status](https://travis-ci.org/HolmesProcessing/Holmes-Totem.svg?branch=master)](https://travis-ci.org/HolmesProcessing/Holmes-Totem)

## Overview
The Holmes-TOTEM Planner is responsible for turning data into information by performing feature extraction against submitted objects. When tasked, Holmes-TOTEM schedules the execution of its services which are capable of performing static and dynamic analysis as well as gather data from third parties.

This particular Investigation Planner is optimized for executing Services that complete in a few seconds, i.e. static analysis and 3rd party queries. When dealing with services that take longer to complete, we recommend pairing the Holmes-TOTEM Planner with [Holmes-TOTEM-Long](https://github.com/HolmesProcessing/Holmes-Totem-Long).

## Dependencies
Holmes-TOTEM requires an HTTP server for delivering files, a database for storing results, and a queuing server for organizing tasking. When building and executing Holmes-Totem, we require [Java 8](https://docs.oracle.com/javase/8/docs/technotes/guides/install/install_overview.html) and recommend the [SBT](http://www.scala-sbt.org/) build tool. Most services rely on [Docker](https://docs.docker.com/) and [Docker-Compose](https://docs.docker.com/compose/).

### Serving Files and Storing Results
[Holmes-Storage](https://github.com/HolmesProcessing/Holmes-Storage) is the Holmes Processing recommendation for managing the sample repository and storing Holmes-TOTEM results. While not strictly required, Holmes-Storage will ease the creation of the databases and provide the information in the expected format for other Holmes Processing solutions. 

### Queuing Server
[RabbitMQ](https://www.rabbitmq.com/) is the queuing server of choice for Holmes Processing. Other AMQP complaint services should work but are unsupported and untested. For sending tasking to the queuing server, we recommend using [Holmes-Gateway](https://github.com/HolmesProcessing/Holmes-Gateway) for optimizing the tasking and handling user authentication. 

### Compiling and Executing
Holmes-Totem requires [Java 8](https://docs.oracle.com/javase/8/docs/technotes/guides/install/install_overview.html) and we recommend using the [SBT](http://www.scala-sbt.org/) build tool.

## Basic Compilation and Setup
1. Clone the Git Repository and Change Directory
```
git clone https://github.com/HolmesProcessing/Holmes-Totem.git
cd Holmes-Totem
```

2. Perform Totem Configuration
Create configurations from the example defaults. This will configure the system to use all available Holmes-TOTEM services.
```
cp ./config/totem.conf.example ./config/totem.conf
cp ./config/docker-compose.yml.example ./config/docker-compose.yml.example
```
Please perform any adjustments to the configuration to match your environment and needs. You will most likely need to adjust the `rabbit_settings`.

3. Perform Service Configuration
Holmes-TOTEM services will require configuring. In most cases this should be as simple as renaming the `service.conf.example` file to `service.conf`. For more information and details on the options available, please visit the directory and read the `README.md` for each service `./src/main/scala/org/holmesprocessing/totem/services/`

4. Compile Holmes-TOTEM
Use SBT to download all dependencies and compile the source into a working JAR file.
```
sbt assembly
```

5. Start the Services
```
docker-compose -f ./config/docker-compose.yml up -d
```

6. Execute Totem
```
java -jar target/scala-2.11/totem-assembly-1.0.jar
```

## Services:
Included services mostly depend on pythons HTTP framework "Tornado", this can be installed via `pip install tornado`.
Also most services provide a Dockerfile you can use to build the service without having to worry about the dependencies.
Check the `README.md` file of each service to get an introduction how to run the service.

## Dataflow:
The general case data workflow between actors is as follows:

Consumer <-> WorkGroup <-> WorkActor -> Producer

## Config Settings:
All of the below settings can be seen within the `totem.conf.example` file in the `<TOTEM_ROOT>/config/` directory. It is advised that you copy the config and create your own `totem.conf`.
The required settings have been replicated below - there are no defaults hardcoded into TOTEM


```
totem {
  version = "1.0.0"
  download_directory = "/tmp/"
  requeueKey = "requeue.static.totem"
  misbehaveKey = "misbehave.static.totem"

  rabbit_settings {
    host {
      server = "127.0.0.1"
      port = 5672
      username = "guest"
      password = "guest"
      vhost = "/"
    }
    exchange {
      name = "totem"
      type = "topic"
      durable = true
    }
    workqueue {
      name = "totem_input"
      routing_key = "work.static.totem"
      durable = true
      exclusive = false
      autodelete = false
    }
    resultsqueue {
      name = "totem_output"
      routing_key = "*.result.static.totem"
      durable = true
      exclusive = false
      autodelete = false
    }
  }

  services {
    yara {
      uri = ["http://127.0.0.1:7701/yara/"]
      resultRoutingKey = "yara.result.static.totem"
    }
  }
}
```

## Acknowledgment
Holmes-Totem is derived from the Novetta open source project Totem and The Holmes Group LLC is not in any way related or endorsed by Novetta. We gracelessly thank Novetta for then wonderful contribution and we could not have created this project without their support. 

Holmes Processing would also like to thank the [CRITs](https://crits.github.io/) team for their valuable discussions and support they provided.
