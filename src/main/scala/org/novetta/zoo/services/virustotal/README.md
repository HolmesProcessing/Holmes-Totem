# Holmes-Totem-Service-VTSample

## Description

A very simple Holmes-Totem service which will collect everything Virustotal knows about a sample.
It can also upload unknown samples to Virustotal.

## Usage

Download the only dependencie, httprouter:
```bash
go get github.com/julienschmidt/httprouter
```
Edit `main.go` and fill in the constants with your own values.
```go
const (
	ApiKey               = "APIKEY"
	UploadUnknownSamples = true
	HttpBinding = ":7710"
)
```
Start the server by using `go run`, `go build` or `go install`, whatever you prefer.

If you decide to active `UploadUnknownSamples` make sure to up the time a Holmes-Totem request may run
in your `WorkActor.scala`:
```scala
val config = new AsyncHttpClientConfig.Builder()
  .setRequestTimeout( 500 ) //up this to _at_least_ 5.1min
  .setExecutorService(execServ)
  .setAllowPoolingConnections(true)
  .setConnectTimeout( 500 )
  .setIOThreadMultiplier(4).build()
```
