# VirusTotal service for Holmes-Totem

## Description

A very simple Holmes-Totem service which will collect everything Virustotal knows about a sample. It can also upload unknown samples to Virustotal.

## Usage

Copy `service.conf.example` to `service.conf` and fill in your own values.

If you decide to activate `UploadUnknownSamples` make sure to up the time a Holmes-Totem request may run in your `WorkActor.scala`:
```scala
val config = new AsyncHttpClientConfig.Builder()
  .setRequestTimeout( 500 ) //up this to _at_least_ 5.1min
  .setExecutorService(execServ)
  .setAllowPoolingConnections(true)
  .setConnectTimeout( 500 )
  .setIOThreadMultiplier(4).build()
```

Build and start the docker container using the included Dockerfile. Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.
