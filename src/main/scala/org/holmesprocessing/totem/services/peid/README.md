# PEID service for Holmes-Totem

## Description

This service identifies compilers and packers based on sets of yara rule packs. We have set the default to what we have found performs best, without collisions, in our analysis. However, we have includes additional packs that can be selected by modifying `rules.yar`.

## Usage

Copy `service.conf.example` to `service.conf` and fill in your own values.

Build and start the docker container using the included Dockerfile. Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.
