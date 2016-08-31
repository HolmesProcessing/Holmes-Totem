# Passivetotal service for Holmes-Totem

## Description

A simple service to check PassiveTotal for additional enrichment data.
If you do not have an API key, visit http://www.passivetotal.org to get one.

## Usage

Build and start the docker container using the included Dockerfile.

Upon building the Dockerfile downloads a list of TLDs from iana.org.
To update this list of TLDs, the image needs to be built again.

The service accepts domain names, ip addresses and emails as request objects.
These have to be supplied as a parameter after the request URL.
(If the analysisURL parameter is set to /passivetotal, then a request for the
domain www.passivetotal.org would look like this: /passivetotal/www.passivetotal.org)

The service performs some checks to determine the type of the input object.
If a passed domain name contains an invalid TLD, it is invalid and rejected.
If a passed email address contains an invalid domain, it is rejected.
If a passed IP is in a reserved range, it is rejected. (ietf rfcs 6890, 4291)

Only if a request object is determined valid, it is sent to selected passivetotal
api endpoints. The maximum of simultaneous requests is 9.
If an error is encountered in any of the api queries, the request fails and returns
an appropriate error code. Check the local logs for detailed information.
If the query succeeds, a json struct containing all 9 api end points is returned.
Those endpoints that were not queried are set to null.
