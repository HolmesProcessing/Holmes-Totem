# Yara service for Holmes-Totem

## Description

Performs a yara scan from a master list that is either local or remote. The service also allows for tasking with a custom rule set. 

## Usage

Copy `service.conf.example` to `service.conf` and fill in your own values.

Build and start the docker container using the included Dockerfile. Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.
