package main

/*
Please note that in order to build this service, you should either build it with
Docker or use the attached Makefile (GNU Make: make get-dependencies build-service)
*/

/*
 * Imports for messuring execution time of requests
 */
import (
    "time"
)

/*
 * Imports for reading the config, logging and command line argument parsing.
 */
import (
    "os"
    "path/filepath"
    "log"
    "flag"
    "fmt"
    "passivetotal-service/config"
)

/*
 * Imports for serving on a socket and handling routing of incoming request.
 */
import (
    "net/http"
    "github.com/julienschmidt/httprouter"
    "encoding/json"
)

/*
 * Imports relevant for service execution
 */
import (
    "sync"
    "passivetotal-service/passivetotal"
)


// global variables
var (
    cfg        *Config
    infoLogger *log.Logger
)


// config structs
type Metadata struct {
    Name                string
    Version             string
    Description         string
    Copyright           string
    License             string
}
type Settings struct {
    Port                string
    InfoURL             string
    AnalysisURL         string
    APIUser             string
    APIKey              string
    RequestTimeout      int
}
type Config struct {
    Metadata            Metadata
    Settings            Settings
}


// main logic
func main () {
    var configPath string

    // setup logging
    infoLogger = log.New(os.Stdout, "", log.Ltime|log.Lshortfile)

    // load config
    flag.StringVar(&configPath, "config", "", "Path to the configuration file")
    flag.Parse()
    if configPath == "" {
        configPath, _ = filepath.Abs(filepath.Dir(os.Args[0]))
        configPath    = filepath.Join(configPath, "service.conf")
    }
    cfg = &Config{}
    config.Parse(cfg, configPath)

    // modify analysis routing url
    analysisURL := cfg.Settings.AnalysisURL
    if analysisURL[len(analysisURL)-1] != '/' {
        analysisURL += "/"
    }
    analysisURL += ":object"

    // setup http handlers
    router := httprouter.New()
    router.GET(analysisURL, handlerAnalyze)
    router.GET(cfg.Settings.InfoURL, handlerInfo)
    port := cfg.Settings.Port
    address := fmt.Sprintf(":%s",port)
    infoLogger.Printf("Binding to %s\n", address)
    infoLogger.Fatal(http.ListenAndServe(address, router))
}


func handlerInfo (f_response http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    result := fmt.Sprintf(`
        <p>%s - %s</p>
        <hr>
        <p>%s</p>
        <hr>
        <p>%s</p>
        `,
        cfg.Metadata.Name,
        cfg.Metadata.Version,
        cfg.Metadata.Description,
        cfg.Metadata.License)
    fmt.Fprint(f_response, result)
}


func handlerAnalyze (f_response http.ResponseWriter, request *http.Request, params httprouter.Params) {
    infoLogger.Println("Serving request:", request)
    startTime := time.Now()

    // retrieve result and marshal it
    result        := doPassiveTotalLookup(params.ByName("object"))
    resultJSON, _ := json.Marshal(result)

    // send back a response of type text/json
    f_response.Header().Set("Content-Type","text/json; charset=utf-8")
    fmt.Fprint(f_response, string(resultJSON))

    elapsedTime := time.Since(startTime)
    infoLogger.Printf("Done in %s.\n", elapsedTime)
}


func doPassiveTotalLookup(object string) *passivetotal.ApiQuery {
    user   := cfg.Settings.APIUser
    apikey := cfg.Settings.APIKey
    timeout:= cfg.Settings.RequestTimeout
    query  := passivetotal.NewApiQuery(user, apikey, object, timeout)
    wg     := &sync.WaitGroup{}

    wg.Add(11)

    go func(wg *sync.WaitGroup) {
        defer wg.Done()
        query.DoPassiveDnsQuery()
        }(wg)

    go func(wg *sync.WaitGroup) {
        defer wg.Done()
        query.DoWhoisQuery()
        }(wg)

    go func(wg *sync.WaitGroup) {
        defer wg.Done()
        query.DoWhoisEmailSearch()
        }(wg)

    go func(wg *sync.WaitGroup) {
        defer wg.Done()
        query.DoSslQuery()
        }(wg)

    go func(wg *sync.WaitGroup) {
        defer wg.Done()
        query.DoSslHistoryQuery()
        }(wg)

    go func(wg *sync.WaitGroup) {
        defer wg.Done()
        query.DoSubdomainQuery()
        }(wg)

    go func(wg *sync.WaitGroup) {
        defer wg.Done()
        query.DoEnrichmentQuery()
        }(wg)

    go func(wg *sync.WaitGroup) {
        defer wg.Done()
        query.DoTrackerQuery()
        }(wg)

    go func(wg *sync.WaitGroup) {
        defer wg.Done()
        query.DoComponentQuery()
        }(wg)

    go func(wg *sync.WaitGroup) {
        defer wg.Done()
        query.DoOsintQuery()
        }(wg)

    go func(wg *sync.WaitGroup) {
        defer wg.Done()
        query.DoMalwareQuery()
        }(wg)

    wg.Wait()
    return query
}
