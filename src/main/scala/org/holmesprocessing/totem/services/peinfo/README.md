# PEInfo service for Holmes-Totem

## Description

This service extracts meta information contained in PE32 binary files. Currently the work is based on the CRITs implemention of PEInfo, which in turn is based on PEFILE. However, we have modified to fix some minor errors and also perform additional extractions.

## Usage

Build and start the docker container using the included Dockerfile. Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.
