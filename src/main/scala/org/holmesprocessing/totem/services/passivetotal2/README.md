# Passivetotal service for Holmes-Totem

## Description

A simple service to check PassiveTotal for additional enrichment data.
If you do not have an API key, visit http://www.passivetotal.org to get one.

## Usage

Build and start the docker container using the included Dockerfile.
Since this container needs to have access to the sample file,
you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only
mode.
