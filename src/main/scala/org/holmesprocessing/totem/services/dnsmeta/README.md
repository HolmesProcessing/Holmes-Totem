# DNSMeta service for Holmes-Totem

## Description

A simple service for gathering DNS information about a domain. This service is capable of extracting the A, AAAA, CNAME, MX, NS, PTR, SOA, and TXT fields. If the authoritative NS can be identified and located, the TTL values will be set to the max TTL values. If it cannot, the TTL values will reflect the current TTL values for that server. 

## Output
The output will return a json result that is as true as possible to the queried DNS server. In theory this should match the the corresponding RFC for the type. For a list of types and RFC documentation please see [record types](https://en.wikipedia.org/wiki/List_of_DNS_record_types)

As an example:
```json
{
  "SOA": {
    "rdata": [
      {
        "expire": 1800,
        "retry": 900,
        "rname": "dns-admin.google.com.",
        "minimum": 60,
        "refresh": 900,
        "serial": 151073646,
        "mname": "ns2.google.com."
      }
    ],
    "type": "SOA",
    "name": "google.de.",
    "ttl": 60,
    "class": "IN"
  },
  "NS": {
    "rdata": [
      {
        "target": "ns1.google.com."
      },
      {
        "target": "ns4.google.com."
      },
      {
        "target": "ns2.google.com."
      },
      {
        "target": "ns3.google.com."
      }
    ],
    "type": "NS",
    "name": "google.de.",
    "ttl": 345600,
    "class": "IN"
  },
  "A": {
    "rdata": [
      {
        "address": "172.217.19.99"
      }
    ],
    "type": "A",
    "name": "google.de.",
    "ttl": 300,
    "class": "IN"
  },
  "auth": [
    "ns1.google.com.",
    "216.239.32.10"
  ],
  "TXT": {
    "rdata": [
      {
        "strings": "\"v=spf1 -all\""
      }
    ],
    "type": "TXT",
    "name": "google.de.",
    "ttl": 300,
    "class": "IN"
  },
  "AAAA": {
    "rdata": [
      {
        "address": "2a00:1450:4016:802::2003"
      }
    ],
    "type": "AAAA",
    "name": "google.de.",
    "ttl": 300,
    "class": "IN"
  },
  "MX": {
    "rdata": [
      {
        "preference": 10,
        "exchange": "aspmx.l.google.com."
      },
      {
        "preference": 40,
        "exchange": "alt3.aspmx.l.google.com."
      },
      {
        "preference": 50,
        "exchange": "alt4.aspmx.l.google.com."
      },
      {
        "preference": 20,
        "exchange": "alt1.aspmx.l.google.com."
      },
      {
        "preference": 30,
        "exchange": "alt2.aspmx.l.google.com."
      }
    ],
    "type": "MX",
    "name": "google.de.",
    "ttl": 600,
    "class": "IN"
  }
}
```

## Usage

Build and start the docker container using the included Dockerfile.
