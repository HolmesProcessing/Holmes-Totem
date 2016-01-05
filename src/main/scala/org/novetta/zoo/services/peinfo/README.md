# PEinfo service for Holmes-Totem

## Description

A simple service to extact information from a sample using PEinfo.

## Usage

Build and start the docker container using the included Dockerfile.
Since this container needs to have access to the sample file, you
need to run this contiainer with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in
read-only mode.
