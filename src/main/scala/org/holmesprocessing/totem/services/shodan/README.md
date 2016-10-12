#Shodan service for Holmes-Totem

###Description
A simple service for gathering Shodan information about an ip address.

###Output
```json
{
 "host": {
  "region_code": "<string>",
  "ip": "<string>",
  "area_code": "<int>",
  "country_name": "<string>", "hostnames": ["<string>"],
  "postal_code": "<string>",
  "dma_code": "<int>",
  "country_code": "<string>",
  "data": [
   {
    "product": "<string>",
    "os": "<string>",
    "timestamp": "<string>",
    "isp": "<string>",
    "asn": "<string>",
    "banner": "<string>",
    "hostnames": ["<string>"],
    "devicetype": "<string>",
    "location": {
     "city": "<string>",
     "region_code": "<string>",
     "area_code": "<int>",
     "longitude": "<double>",
     "country_code3": "<string>",
     "country_name": "<string>",
     "postal_code": "<string>",
     "dma_code": "<int>",
     "country_code": "<string>",
     "latitude": "<double>"
    },
    "ip": "<string>",
    "domains": ["<string>"],
    "org": "<string>",
    "port": "<int>",
    "opts": {"<string>"}
   },
   {
    "os": "<string>",
    "timestamp": "<string>",
    "isp": "<string>",
    "asn": "<string>",
    "banner": "<string>",
    "hostnames": ["<string>"],
    "location": {
     "city": "<string>",
     "region_code": "<string>",
     "area_code": "<int>",
     "longitude": "<double>",
     "country_code3": "<string>",
     "country_name": "<string>",
     "postal_code": "<string>",
     "dma_code": "<int>",
     "country_code": "<string>",
     "latitude": "<double>"
    },
    "ip": "<string>",
    "domains": ["<string>"],
    "org": "<string>",
    "port": "<int>",
    "opts": {"<string>"}
   }
  ],
  "city": "<string>",
  "longitude": "<double>",
  "country_code3": "<string>",
  "latitude": "<double>",
  "os": "<string>",
  "ports": ["<int>", "<int>"]
 },
}
```

###Usage
Copy service.conf.example to service.conf and fill in your own values.
When assigning the SHODAN_API_KEY to the apikey in service.config 
do not use quotation marks around the SHODAN_API_KEY.
Build and start the docker container using the included Dockerfile.
If the service has frequent timeouts you have to adjust totem.conf:
+ totem.download_settings.connection_timeout
+ totem.download_settings.request_timeout
+ totem.tasking_settings.default_service_timeout
