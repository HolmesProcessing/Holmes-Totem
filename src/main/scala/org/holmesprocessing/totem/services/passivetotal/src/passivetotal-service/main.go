package main

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
    "flag"
    "fmt"
    "log"
    "os"
    "passivetotal-service/config"
    "path/filepath"
)

/*
 * Imports for serving on a socket and handling of incoming request.
 */
import (
    "encoding/json"
    "github.com/julienschmidt/httprouter"
    "io/ioutil"
    "net/http"
)

/*
 * Imports relevant for service execution
 */
import (
    "passivetotal-service/passivetotal"
    "sync"
)

// global variables
var (
    cfg        *Config
    infoLogger *log.Logger
)

// config structs
type Metadata struct {
    Name        string
    Version     string
    Description string
    Copyright   string
    License     string
}
type Settings struct {
    Port           string
    InfoURL        string
    AnalysisURL    string
    APIUser        string
    APIKey         string
    RequestTimeout int
}
type Config struct {
    Metadata Metadata
    Settings Settings
}

// main logic
func main() {
    var configPath string

    // setup logging
    infoLogger = log.New(os.Stdout, "", log.Ltime|log.Lshortfile)

    // load config
    flag.StringVar(&configPath, "config", "", "Path to the configuration file")
    flag.Parse()
    if configPath == "" {
        configPath, _ = filepath.Abs(filepath.Dir(os.Args[0]))
        configPath = filepath.Join(configPath, "service.conf")
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
    address := fmt.Sprintf(":%s", port)
    infoLogger.Printf("Binding to %s\n", address)
    infoLogger.Fatal(http.ListenAndServe(address, router))
}

func handlerInfo(f_response http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

func handlerAnalyze(f_response http.ResponseWriter, request *http.Request, params httprouter.Params) {
    infoLogger.Println("Serving request:", request)
    startTime := time.Now()

    // Get settings and do PT queries.
    // Marshal result right away, after testing if there was an error.
    result, status := doPassiveTotalLookup(request, params)
    var resultJSON []byte
    if result != nil {
        resultJSON, _ = json.Marshal(result)
    } else {
        resultJSON = []byte("{}")
    }

    // Send back a response of type text/json
    f_response.Header().Set("Content-Type", "text/json; charset=utf-8")
    f_response.WriteHeader(status)
    f_response.Write(resultJSON)

    elapsedTime := time.Since(startTime)
    infoLogger.Printf("Done in %s.\n", elapsedTime)
}

func doPassiveTotalLookup(r *http.Request, p httprouter.Params) (interface{}, int) {
    // Generic result object, returned in case of an error instead of the query
    // object:
    var errResult struct {
        Error string `json:"error"`
    }

    // Create a settings object to use with the query, parse parameters passed
    // via the request body into it (all options can be overriden):
    aqs := &passivetotal.ApiQuerySettings{
        Object:   p.ByName("object"),
        Username: cfg.Settings.APIUser,
        ApiKey:   cfg.Settings.APIKey,
        Timeout:  cfg.Settings.RequestTimeout,
    }

    if r.Body != nil {
        if bytes, err := ioutil.ReadAll(r.Body); err != nil {
            msg := "Unexpected error reading the request body: " + err.Error()
            infoLogger.Println(msg)
            errResult.Error = msg
            return errResult, 400
        } else if len(bytes) > 0 {
            if err = json.Unmarshal(bytes, aqs); err != nil {
                msg := "Unexpected error parsing request settings: " + err.Error()
                infoLogger.Println(msg)
                errResult.Error = msg
                return errResult, 400
            }
        }
    }

    // Create a new query object based on the settings, also check for errors
    // during query creation. Only errors possible are due to invalid input
    // (either filtered or unknown type).
    query, err := passivetotal.NewApiQuery(aqs)
    if err != nil {
        infoLogger.Println("Dropping query due to: " + err.Error())
        errResult.Error = err.Error()
        return errResult, 422 // Status Code: Unprocessable Entity
    }

    wg := &sync.WaitGroup{}
    wg.Add(9)

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

    // TODO: ssl query only accepts a certificate hash (sha1), need a per-request option to make this useful
    // go func(wg *sync.WaitGroup) {
    //     defer wg.Done()
    //     query.DoSslQuery()
    // }(wg)

    // TODO: same as for DoSslQuery above, additionally IP seems to not work unlike specified in the API documentation
    // go func(wg *sync.WaitGroup) {
    //     defer wg.Done()
    //     query.DoSslHistoryQuery()
    // }(wg)

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

    // By default assume success, unless the length of errors is not 0.
    // In that case check if it is a known error (user has reached his paid
    // quota / user credentials invalid), or if it is an unknown error, in which
    // case we should return 500 as there should be no error condition that is
    // unknown (other than maybe a 500 by the PassiveTotal servers, in which
    // case we should have a 500 too, to indicate the severity of the error).
    if len(query.Errors) != 0 {
        status := 200
        if query.QuotaReached {
            errResult.Error = "Quota Reached"
            status = 402

        } else if query.InvalidAuthentication {
            errResult.Error = "Invalid Authentication"
            status = 401

        } else if query.ConnectionError {
            errResult.Error = "PassiveTotal API Unreachable"
            status = 502

        } else {
            errResult.Error = "Unexpected Error"
            status = 500
        }
        return errResult, status
    }

    // Everything is fine.
    return query, 200
}
