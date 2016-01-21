# PEiD service for Holmes-Totem

## Description

A simple service to id compilers and packers based on yara rules.

## Usage

Build and start the docker container using the included Dockerfile.
Since this container needs to have access to the sample file, you
need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in
read-only mode.
