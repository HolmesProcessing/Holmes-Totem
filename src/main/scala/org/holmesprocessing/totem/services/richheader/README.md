# Rich Header service for Holmes-Totem

## NOTICE

For more details about the Rich Header, most updated version of the extractor, and ML code, please see the [RichHeader-Service_Collection Repository](https://github.com/HolmesProcessing/RichHeader-Service_Collection)

## Description

The Rich Header service extracts the Rich Header from PE32 files. The resulting output is presented in JSON. 

## Output
```json
{
    "compids": [
        {
            "mcv": "<str>",
            "pid": "<str>",
            "cnt": "<str>",
        }
    ],
    "compids_dup": "<boolean>",
    "csum_calc": "<int>",
    "csum_file": "<int>",
    "csum_valid": "<boolean>",
    "error": "<int>",
    "offset": "<int>",
}
```

## Usage

Build and start the docker container using the included Dockerfile. Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.
