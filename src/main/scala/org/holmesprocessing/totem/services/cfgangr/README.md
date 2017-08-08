# CFG Angr service for Holmes-Totem

## Description

A simple service that utilizes the open-source library 'angr' to retrieve the control flow graph (CFG) from a binary. This service dumps the CFG into JSON format.

## Usage

Build and start the docker container using the included Dockerfile. Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.
