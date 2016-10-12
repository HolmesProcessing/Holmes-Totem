# Objdump service for Holmes-Totem

## Description

A simple service to get the Objdump output of a binary file.

## Output
```json
{
    "fileformat": "<string>",
    "number_of_opcodes": "<int64>",
    "truncated": "<boolean>",
    "sections": {
        "name:<string>": {
            "name": "<string>",
            "flags": ["<string>"],
            "truncated": "<boolean>",
            "blocks": [
                {
                    "name": "<string>",
                    "offset": "<string>",
                    "start_index": "<int64>",
                    "truncated": "<boolean>",
                    "opcodes": ["<string>"]
                }
            ]
        }
    }
}
```
Each file may have one or many sections each with a unique name.
Each section may have one or many blocks.
All sections are listed, but may be truncated, this depends on the service.conf opcodes limit setting.
Sections that do not have the CODE flag set, will not be listed as truncated but will have no blocks.
If during parsing, the max number of opcodes is reached, the current block is marked as truncated, the section is left and all further sections are marked as truncated and have 0 blocks.

## Usage

Copy the `service.conf.example` to `service.conf` and adjust the values to your needs.
Build and start the docker container using the included Dockerfile.
Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.
