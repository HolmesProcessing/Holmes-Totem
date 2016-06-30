# Holmes-TOTEM: A Framework for large-scale file analysis [![Build Status](https://travis-ci.org/HolmesProcessing/Holmes-Totem.svg?branch=master)](https://travis-ci.org/HolmesProcessing/Holmes-Totem)

## Compilation:

If you have SBT installed, the command `sbt assembly` executed from the base directory will compile the source into a working JAR file.

If you do not already have SBT, [the instructions here](http://www.scala-sbt.org/release/tutorial/Setup.html) are very good, and will get you set up.

After building, TOTEM can be run via:
`java -jar target/scala-2.11/totem-assembly-1.0.jar config/totem.conf`


## Dependencies
TOTEM depends on at least two external services - an HTTP fileserver, and a queueing server. TOTEM currently supports RabbitMQ as it's queueing server of choice.
[Installation documents and packages for RabbitMQ can be found here.](http://www.rabbitmq.com/download.html)

Finally, TOTEM requires an HTTP server which it will use to access files described in its Jobs. Installation of an included HTTP file server is discussed in the Python Services section, but there is no reason that the user could not use another server of their choice.

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

  enrichers {
    yara {
      uri = ["http://127.0.0.1:7701/yara/"]
      resultRoutingKey = "yara.result.static.totem"
    }
  }
}
```

## Acknowledgment
Holmes-Totem is derived from the Novetta open source project Totem and The Holmes Group LLC is not in any way related or endorsed by Novetta. We gracelessly thank Novetta for then wonderful contribution and we could not have created this project without their support. 

Holmes Processing would also like to thank the [CRITs] team for their valuable discussions and support they provided.
