package passivetotal

import (
    "log"
    "os"
    "passivetotal-service/passivetotal/client"
    "passivetotal-service/passivetotal/queryobject"
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
func NewApiQuery(user, apikey, object string, timeout int) *ApiQuery {
    self        := &ApiQuery{}
    self.object  = queryobject.New(object)
    self.client  = client.New(user, apikey, timeout)
    return self
}


// The ApiQuery struct. Use passivetotal.NewApiQuery(user,apikey,object,timeout)
// to create an instance.
// All fields have their appropriate tags set for json marshalling.
type ApiQuery struct {
    Dns                interface{}   `json:"dns"`
    Whois              interface{}   `json:"whois"`
    WhoisEmailSearch   interface{}   `json:"whois_email_search"`
    Ssl                interface{}   `json:"ssl"`
    SslHistory         interface{}   `json:"ssl_history"`
    Subdomain          interface{}   `json:"subdomain"`
    Enrichment         interface{}   `json:"enrichment"`
    Tracker            interface{}   `json:"tracker"`
    Component          interface{}   `json:"component"`
    Osint              interface{}   `json:"osint"`
    Malware            interface{}   `json:"malware"`

    object *queryobject.Object  `json:"-"`
    client *client.Client       `json:"-"`
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
    if apiResult.HttpError != nil {
        infoLogger.Printf("Error running %s, cannot connect to the API: %v\n",
                           apiResult.QueryDescription,
                           apiResult.HttpError)
    } else {
        if apiResult.StatusCode != 200 {
            if apiResult.Error {
                infoLogger.Printf("Error running %s: (%d) %s, %s\n",
                                   apiResult.QueryDescription,
                                   apiResult.StatusCode,
                                   apiResult.ErrorMessage,
                                   apiResult.DeveloperMessage)
            } else {
                infoLogger.Printf("Error running %s, unknown API error: (%d) %s\n",
                                   apiResult.QueryDescription,
                                   apiResult.StatusCode,
                                   apiResult.Status)
            }
        }
        if apiResult.JsonError != nil {
            infoLogger.Printf("Error running %s, parser error: %v",
                               apiResult.QueryDescription,
                               apiResult.JsonError)
        }
    }
    return apiResult.Json
}


/* -----------------------------------------------------------------------------
 * Query function definitions for PassiveTotal query object (ApiQuery).
 */

// Retrieve passive dns information.
func (self *ApiQuery) DoPassiveDnsQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.IP, queryobject.Indicator) {
        url := "https://api.passivetotal.org/v2/dns/passive?query="+self.object.Obj
        self.Dns = self.checkForErrors(self.client.SendApiRequest(url, "DNS query"))
    }
}

// Retrieve whois information.
func (self *ApiQuery) DoWhoisQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.Indicator) {
        url := "https://api.passivetotal.org/v2/whois?query="+self.object.Obj
        self.Whois = self.checkForErrors(self.client.SendApiRequest(url, "Whois query"))
    }
}

// Retrieve whois email search results.
func (self *ApiQuery) DoWhoisEmailSearch() {
    if self.hasObjType(queryobject.Email, queryobject.Indicator) {
        url := "https://api.passivetotal.org/v2/whois/search?query="+self.object.Obj+"&field=email"
        self.WhoisEmailSearch = self.checkForErrors(self.client.SendApiRequest(url, "Whois email search"))
    }
}

// Retrive SSL information.
func (self *ApiQuery) DoSslQuery() {
    if self.hasObjType(queryobject.IP, queryobject.Indicator) {
        url := "https://api.passivetotal.org/v2/ssl-certificate?query="+self.object.Obj
        self.Ssl = self.checkForErrors(self.client.SendApiRequest(url, "SSL Certificate query"))
    }
}

// Retrieve SSL history.
func (self *ApiQuery) DoSslHistoryQuery() {
    if self.hasObjType(queryobject.IP, queryobject.Indicator) {
        url := "https://api.passivetotal.org/v2/ssl-certificate/history?query="+self.object.Obj
        self.SslHistory = self.checkForErrors(self.client.SendApiRequest(url, "SSL Certificate history query"))
    }
}

// Retrieve subdomains.
func (self *ApiQuery) DoSubdomainQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.Indicator) {
        url := "https://api.passivetotal.org/v2/enrichment/subdomains?query="+self.object.Obj
        self.Subdomain = self.checkForErrors(self.client.SendApiRequest(url, "Subdomain query"))
    }
}

// Retrieve enrichment data.
func (self *ApiQuery) DoEnrichmentQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.Indicator, queryobject.IP) {
        url := "https://api.passivetotal.org/v2/enrichment?query="+self.object.Obj
        self.Enrichment = self.checkForErrors(self.client.SendApiRequest(url, "Enrichment query"))
    }
}

// Retrieve trackers.
func (self *ApiQuery) DoTrackerQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.Indicator, queryobject.IP) {
        url := "https://api.passivetotal.org/v2/host-attributes/trackers?query="+self.object.Obj
        self.Tracker = self.checkForErrors(self.client.SendApiRequest(url, "Tracker query"))
    }
}

// Retrieve components.
func (self *ApiQuery) DoComponentQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.Indicator, queryobject.IP) {
        url := "https://api.passivetotal.org/v2/host-attributes/components?query="+self.object.Obj
        self.Component = self.checkForErrors(self.client.SendApiRequest(url, "Components query"))
    }
}

// Retrieve opensource intelligence data.
func (self *ApiQuery) DoOsintQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.Indicator, queryobject.IP) {
        url := "https://api.passivetotal.org/v2/enrichment/osint?query="+self.object.Obj
        self.Osint = self.checkForErrors(self.client.SendApiRequest(url, "Osint query"))
    }
}

// Retrieve malware information.
func (self *ApiQuery) DoMalwareQuery() {
    if self.hasObjType(queryobject.Domain, queryobject.Indicator, queryobject.IP) {
        url := "https://api.passivetotal.org/v2/enrichment/malware?query="+self.object.Obj
        self.Malware = self.checkForErrors(self.client.SendApiRequest(url, "Malware query"))
    }
}
