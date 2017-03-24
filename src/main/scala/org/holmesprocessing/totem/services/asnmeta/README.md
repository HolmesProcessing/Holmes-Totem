# ASNMeta service for Holmes-Totem

## Description

A simple service for gathering ANS information for an IP v4/6 address.

## Output
```json
    "bgp_prefix": "<str>", 
    "asn_peers": [
        "<str>", 
        "<str>",
    ], 
    "registry": "<str>", 
    "asn_number": "<str>", 
    "data_allocated": "<str>", 
    "cc": "<str>",
```

## Usage

Build and start the docker container using the included Dockerfile.
