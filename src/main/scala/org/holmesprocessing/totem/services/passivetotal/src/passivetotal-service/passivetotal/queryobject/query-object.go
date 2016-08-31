package queryobject

// Imports for logging
import (
    "log"
    "os"
)

// Imports required to determine the type of the object contained in a *Object.
import (
    "errors"
    "io/ioutil"
    "net"
    "net/mail"
    "strings"
)

const (
    // The constants defining what kind of object is saved in a Object.
    Domain int = iota
    Email
    Indicator
    IP
)

var (
    // global type constants map as well as a logger instance
    // since iota starts with 0, we can just use a string slice replicating the
    // offset
    typeMap = []string{
        "Domain",
        "Email",
        "Indicator",
        "IP",
    }
    infoLogger *log.Logger

    // address ranges to be filtered out
    ipv4NetFiltered = []*net.IPNet{}
    ipv6NetFiltered = []*net.IPNet{}

    // global tld map, fetched from iana
    tldMap = make(map[string]bool)
)

func init() {
    // initialize our logger instance
    infoLogger = log.New(os.Stdout, "", log.Ltime|log.Lshortfile)

    // init address ranges to be filtered out
    // for ipv4 see: https://tools.ietf.org/html/rfc6890
    // for ipv6 see: https://tools.ietf.org/html/rfc4291
    var v4FilteredSubnets = []string{
        // this-host-this-net
        "0.0.0.0/8",
        // loopback
        "127.0.0.0/8",
        // private use networks
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        // limited broadcast
        "255.255.255.255/32",
    }
    var v6FilteredSubnets = []string{
        // loopback
        "::1/128",
        // unspecified address
        "::/128",
        // multicast
        "FF00::/8",
        // link-local
        "FE80::/10",
    }
    for _, subnet := range v4FilteredSubnets {
        _, ipnet, _ := net.ParseCIDR(subnet)
        ipv4NetFiltered = append(ipv4NetFiltered, ipnet)
    }
    for _, subnet := range v6FilteredSubnets {
        _, ipnet, _ := net.ParseCIDR(subnet)
        ipv6NetFiltered = append(ipv6NetFiltered, ipnet)
    }

    // grab iana tld registry
    infoLogger.Println("Mapping TLDs, reading TLDList.txt ...")
    tlds, err := ioutil.ReadFile("TLDList.txt")
    if err != nil {
        log.Println("Error reading TLDList.txt: " + err.Error())
    } else {
        for _, tld := range strings.Split(string(tlds), "\n") {
            tld = strings.TrimSpace(tld)
            if tld != "" && tld[0] != '#' {
                tldMap[tld] = true
            }
        }
    }
}

// Create a new instance of Object, detect the type of the supplied
// object and return the instance.
//
// Returns an error if detectObjectType returns an error.
func New(object, defaultType string) (*Object, error) {
    self := &Object{}
    self.Obj = object
    err := self.detectObjectType(defaultType)
    return self, err
}

// Simple wrapper around the actual query value (string), to enable associating
// a specific type with it. Use queryobject.New(object) to create one.
type Object struct {
    Obj  string
    Type int
}

// Return a string representation of the type that this object represents.
func (self *Object) TypeString() string {
    return typeMap[self.Type]
}

// constant for error output
const (
    errBaseStr = "QueryObject Error: "
)

// Internal helper function to determine the object type.
//
// Supports IPv4, IPv6 in punctuated string representation.
// Supports CIDR IP address ranges
// Supports Emails and "Name <Email>"
// Supports Domains and checks the TLD
// If the request has the appropriate parameter set, all remaining
// unidentifiable objects are set to the defaultType.
//
// Returns an error if one of the checks fails or if no type matches and the
// defaultType is not set.
func (self *Object) detectObjectType(defaultType string) error {
    // Avoid problems in functions below.
    if self.Obj == "" {
        return errors.New(errBaseStr + "Empty String")
    }

    // TODO: support for IP's in decimal form
    if ip := net.ParseIP(self.Obj); ip != nil {
        if isFiltered(ip) {
            return errors.New(errBaseStr + "Filtered IP: " + self.Obj)
        }
        self.Type = IP
        self.Obj = ip.String()

    } else if ip, _, err := net.ParseCIDR(self.Obj); err == nil {
        if isFiltered(ip) {
            return errors.New(errBaseStr + "Filtered IP: " + self.Obj)
        }
        self.Type = IP

    } else {
        if isDomainName(self.Obj) {
            if !inTldMap(self.Obj) {
                return errors.New(errBaseStr + "Invalid TLD")
            }
            self.Type = Domain

        } else if email, err := mail.ParseAddress(self.Obj); err == nil {
            parts := strings.SplitN(email.Address, "@", 2)
            domain := parts[len(parts)-1]
            parts = strings.Split(domain, ".")
            if len(parts) < 2 || !isDomainName(domain) || !inTldMap(domain) {
                return errors.New(errBaseStr + "Email Address Has Invalid Domain")
            }
            self.Type = Email
            self.Obj = email.Address

        } else {
            if defaultType == "Domain" {
                self.Type = Domain
            } else if defaultType == "Email" {
                self.Type = Email
            } else if defaultType == "Indicator" {
                self.Type = Indicator
            } else if defaultType == "IP" {
                self.Type = IP
            } else {
                return errors.New("QueryObject Error: Unknown Type: " + self.Obj)
            }
        }
    }

    infoLogger.Printf("QueryObject.detectObjectType: %s => %s (%d)\n",
        self.Obj, self.TypeString(), self.Type)
    return nil
}

// Helper function, checks if the given IP is within one of the reserved IP
// address ranges. See ipv4NetFiltered and ipv6NetFiltered variable
// initialization in init().
func isFiltered(ip net.IP) bool {
    if len(ip) == net.IPv4len {
        for _, net := range ipv4NetFiltered {
            if net.Contains(ip) {
                return true
            }
        }

    } else if len(ip) == net.IPv6len {
        for _, net := range ipv6NetFiltered {
            if net.Contains(ip) {
                return true
            }
        }
    }

    return false
}

// Part of golang standard package net:
// https://golang.org/src/net/dnsclient.go?m=text
func isDomainName(s string) bool {
    // See RFC 1035, RFC 3696.
    if len(s) == 0 {
        return false
    }
    if len(s) > 255 {
        return false
    }

    last := byte('.')
    ok := false // Ok once we've seen a letter.
    partlen := 0
    for i := 0; i < len(s); i++ {
        c := s[i]
        switch {
        default:
            return false
        case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
            ok = true
            partlen++
        case '0' <= c && c <= '9':
            // fine
            partlen++
        case c == '-':
            // Byte before dash cannot be dot.
            if last == '.' {
                return false
            }
            partlen++
        case c == '.':
            // Byte before dot cannot be dot, dash.
            if last == '.' || last == '-' {
                return false
            }
            if partlen > 63 || partlen == 0 {
                return false
            }
            partlen = 0
        }
        last = c
    }
    if last == '-' || partlen > 63 {
        return false
    }

    return ok
}

// Helper function to determine if a given domains tld is registered with iana.
func inTldMap(domain string) bool {
    parts := strings.Split(domain, ".")
    _, ok := tldMap[strings.ToUpper(parts[len(parts)-1])]
    return ok
}
