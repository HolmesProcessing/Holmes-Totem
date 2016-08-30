# Passivetotal service for Holmes-Totem

## Description

A simple service to check PassiveTotal for additional enrichment data.
If you do not have an API key, visit http://www.passivetotal.org to get one.

Upon building the Dockerfile downloads a list of TLDs from iana.org.
To update the list of TLDs recognized by the service it needs to be built again.

## Usage

Build and start the docker container using the included Dockerfile.
