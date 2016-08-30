package passivetotal

import (
    "log"
    "os"
    "passivetotal-service/passivetotal/client"
    "passivetotal-service/passivetotal/queryobject"
    "sync"
)

var (
    infoLogger = log.New(os.Stdout, "", log.Ltime|log.Lshortfile)
)

// Create a new instance of ApiQuery, populate it with meaningful contents and
// return it.
// @param user String containing the PassiveTotal username.
// @param apikey String containing the PassiveTotal api key.
// @param object String containing the query value (Domain, IP, Indicator or Email)
// @param timeout Int timeout in seconds before a query is interrupted and an
//                empty result returned.
//
// Returns an error if queryobject.New returns an error, which only happens if
// detectObjectType returns an error (filtered IP range or unknown type).
func NewApiQuery(cfg *ApiQuerySettings) (*ApiQuery, error) {
    self := &ApiQuery{}
    o, err := queryobject.New(cfg.Object, cfg.DefaultType)
    self.object = o
    self.client = client.New(cfg.Username, cfg.ApiKey, cfg.Timeout)
    self.ObjectType = o.TypeString()
    return self, err
}

// A struct containing settings for an ApiQuery.
type ApiQuerySettings struct {
    Username    string `json="-"`
    ApiKey      string `json="-"`
    Object      string `json="-"`
    Timeout     int    `json="-"`
    DefaultType string `json="default_type"`
}

// The ApiQuery struct. Use passivetotal.NewApiQuery(user,apikey,object,timeout)
// to create an instance.
// All fields have their appropriate tags set for json marshalling.
type ApiQuery struct {
    // Embedd mutex into this object.
    sync.Mutex

    // Result fields.
    Dns              interface{} `json:"dns"`
    Whois            interface{} `json:"whois"`
    WhoisEmailSearch interface{} `json:"whois_email_search"`
    Subdomain        interface{} `json:"subdomain"`
    Enrichment       interface{} `json:"enrichment"`
    Tracker          interface{} `json:"tracker"`
    Component        interface{} `json:"component"`
    Osint            interface{} `json:"osint"`
    Malware          interface{} `json:"malware"`
    // See corresponding TODOs in main.go
    // Ssl                interface{}   `json:"ssl"`
    // SslHistory         interface{}   `json:"ssl_history"`

    // Error fields, not published via json.
    Errors                []string `json:"-"`
    ConnectionError       bool     `json:"-"`
    QuotaReached          bool     `json:"-"`
    InvalidAuthentication bool     `json:"-"`

    // Meta fields, including published object type field.
    ObjectType string              `json:"object_type"`
    object     *queryobject.Object `json:"-"`
    client     *client.Client      `json:"-"`
}

// Internal helper function to check whether a function is supposed to be used
// with the supplied object type.
func (self *ApiQuery) hasObjType(supported ...int) bool {
    for _, s := range supported {
        if self.object.Type == s {
            return true
        }
    }
    return false
}

// Internal helper function to log errors.
func (self *ApiQuery) checkForErrors(apiResult *client.ApiResult) interface{} {
    // Make sure self is locked to avoid undefined behaviour when writing to
    // the Errors slice.
    self.Lock()
    defer self.Unlock()

    hasError := false

    if apiResult.HttpError != nil {
        hasError = true
        self.ConnectionError = true
        infoLogger.Printf("Error running %s, connection error: %v\n",
            apiResult.QueryDescription, apiResult.HttpError)

    } else {
        if apiResult.StatusCode != 200 {
            hasError = true

            if apiResult.StatusCode == 401 {
                self.InvalidAuthentication = true
                infoLogger.Printf("Error running %s, api error: Invalid Authentication!\n",
                    apiResult.QueryDescription)

            } else if apiResult.StatusCode == 403 {
                self.QuotaReached = true
                infoLogger.Printf("Error running %s, api error: Quota Reached!\n",
                    apiResult.QueryDescription)

            } else if apiResult.Error {
                // Unknown other error that is well described.
                infoLogger.Printf("Error running %s, api error: (HTTP %d) %s, %s\n",
                    apiResult.QueryDescription, apiResult.StatusCode,
                    apiResult.ErrorMessage, apiResult.DeveloperMessage)

            } else {
                // Unknown other error that we have no description for.
                infoLogger.Printf("Error running %s, api error : (HTTP %d) %s\n",
                    apiResult.QueryDescription, apiResult.StatusCode,
                    apiResult.Status)
            }
        }
        if apiResult.JsonError != nil {
            hasError = true
            infoLogger.Printf("Error running %s, parser error: %v",
                apiResult.QueryDescription, apiResult.JsonError)
        }
    }

    if hasError {
        self.Errors = append(self.Errors, apiResult.QueryDescription)
        return nil
    }

    return apiResult.Json
}

/* -----------------------------------------------------------------------------
 * Query function definitions for PassiveTotal query object (ApiQuery).
 */

const (
    baseURL = "https://api.passivetotal.org/v2/"
)

// Retrieve passive dns information.
func (self *ApiQuery) DoPassiveDnsQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.IP, queryobject.Indicator) {
        url := baseURL + "dns/passive?query=" + self.object.Obj
        r := self.client.SendApiRequest(url, "DNS query")
        self.Dns = self.checkForErrors(r)
    }
}

// Retrieve whois information.
func (self *ApiQuery) DoWhoisQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.Indicator) {
        url := baseURL + "whois?query=" + self.object.Obj
        r := self.client.SendApiRequest(url, "Whois query")
        self.Whois = self.checkForErrors(r)
    }
}

// Retrieve whois email search results.
func (self *ApiQuery) DoWhoisEmailSearch() {
    if self.hasObjType(queryobject.Email, queryobject.Indicator) {
        url := baseURL + "whois/search?query=" + self.object.Obj + "&field=email"
        r := self.client.SendApiRequest(url, "Whois email search")
        self.WhoisEmailSearch = self.checkForErrors(r)
    }
}

// See corresponding TODOs in main.go
// // Retrieve SSL information.
// func (self *ApiQuery) DoSslQuery() {
//     if self.hasObjType(queryobject.Indicator) {
//         url := baseURL + "ssl-certificate?query="+self.object.Obj
//         r   := self.client.SendApiRequest(url, "SSL Certificate query")
//         self.Ssl = self.checkForErrors(r)
//     }
// }
//
// // Retrieve SSL history.
// func (self *ApiQuery) DoSslHistoryQuery() {
//     if self.hasObjType(queryobject.IP, queryobject.Indicator) {
//         url := baseURL + "ssl-certificate/history?query="+self.object.Obj
//         r   := self.client.SendApiRequest(url, "SSL Certificate history query")
//         self.SslHistory = self.checkForErrors(r)
//     }
// }

// Retrieve subdomains.
func (self *ApiQuery) DoSubdomainQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.Indicator) {
        url := baseURL + "enrichment/subdomains?query=" + self.object.Obj
        r := self.client.SendApiRequest(url, "Subdomain query")
        self.Subdomain = self.checkForErrors(r)
    }
}

// Retrieve enrichment data.
func (self *ApiQuery) DoEnrichmentQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.Indicator, queryobject.IP) {
        url := baseURL + "enrichment?query=" + self.object.Obj
        r := self.client.SendApiRequest(url, "Enrichment query")
        self.Enrichment = self.checkForErrors(r)
    }
}

// Retrieve trackers.
func (self *ApiQuery) DoTrackerQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.Indicator, queryobject.IP) {
        url := baseURL + "host-attributes/trackers?query=" + self.object.Obj
        r := self.client.SendApiRequest(url, "Tracker query")
        self.Tracker = self.checkForErrors(r)
    }
}

// Retrieve components.
func (self *ApiQuery) DoComponentQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.Indicator, queryobject.IP) {
        url := baseURL + "host-attributes/components?query=" + self.object.Obj
        r := self.client.SendApiRequest(url, "Components query")
        self.Component = self.checkForErrors(r)
    }
}

// Retrieve opensource intelligence data.
func (self *ApiQuery) DoOsintQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.Indicator, queryobject.IP) {
        url := baseURL + "enrichment/osint?query=" + self.object.Obj
        r := self.client.SendApiRequest(url, "Osint query")
        self.Osint = self.checkForErrors(r)
    }
}

// Retrieve malware information.
func (self *ApiQuery) DoMalwareQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.Indicator, queryobject.IP) {
        url := baseURL + "enrichment/malware?query=" + self.object.Obj
        r := self.client.SendApiRequest(url, "Malware query")
        self.Malware = self.checkForErrors(r)
    }
}
