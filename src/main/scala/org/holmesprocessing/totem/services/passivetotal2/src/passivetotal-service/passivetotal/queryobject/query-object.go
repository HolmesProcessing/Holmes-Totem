package queryobject

// Imports for logging
import (
    "log"
    "os"
)

// Imports required to determine the type of the object contained in a *Object.
import (
    "net"
    "net/mail"
    "github.com/miekg/dns"
)

// The constants defining what kind of object is saved in a Object.
const (
    Domain int = iota
    Email
    Indicator
    IP
)

var (
    typeMap = make(map[int]string)
    infoLogger *log.Logger
)

func init() {
    typeMap[Domain]    = "Domain"
    typeMap[Email]     = "Email"
    typeMap[Indicator] = "Indicator"
    typeMap[IP]        = "IP"
    infoLogger         = log.New(os.Stdout, "", log.Ltime|log.Lshortfile)
}

// Create a new instance of Object, detect the type of the supplied
// object and return the instance.
func New(object string) *Object {
    self    := &Object{}
    self.Obj = object
    self.detectObjectType()
    return self
}

// Simple wrapper around the actual query value (string), to enable associating
// a specific type with it. Use queryobject.New(object) to create one.
type Object struct {
    Obj  string
    Type int
}

// Internal helper function to try and determine the objects type.
//
// Supports IPv4, IPv6: ddd.ddd.ddd.ddd / xxxx:xxxx:xxxx:xxxx
// Supports CIDR IP address ranges
// Supports Emails and "Name <Email>"
// Supports FQDNs
// All other types are resorted to being an Indicator.
func (self *Object) detectObjectType() {

    if net.ParseIP(self.Obj) != nil {
        self.Type = IP

    } else if _,_,err := net.ParseCIDR(self.Obj); err == nil {
        self.Type = IP  // TODO: is this right?

    } else if dns.IsFqdn(self.Obj) {
        self.Type = Domain

    } else if dns.IsFqdn(self.Obj+".") {
        // check for domains that miss the root label
        // TODO: is this a good idea? (modifying the input this way?)
        self.Type = Domain
        self.Obj  = self.Obj+"."

    } else if email,err := mail.ParseAddress(self.Obj); err == nil {
        self.Type = Email
        self.Obj  = email.Address

    } else {
        // last resort, classify as an indicator
        // TODO: is defaulting to type Indicator really such a good idea? (no weeding out bad stuff?)
        self.Type = Indicator
    }

    infoLogger.Printf("QueryObject.detectObjectType: %s => %s (%d)\n",
               self.Obj, typeMap[self.Type], self.Type)
}
