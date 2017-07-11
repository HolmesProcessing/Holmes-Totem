# PEInfo 2.0 service for Holmes-Totem

## Description

This service extracts meta information contained in PE binary files. Currently the work is based on the implemention of [pefile](https://github.com/erocarrera/pefile).

## Usage

Build and start the docker container using the included Dockerfile. Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.
