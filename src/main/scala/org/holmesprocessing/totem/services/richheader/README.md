# Rich Header service for Holmes-Totem

## Description

The Rich Header service extracts the Rich Header from PE32 files. The resulting 

## Output
```json
    "compids": [
        {
            "mcv": "<string>",
            "pid": "<string>",
            "cnt": "<string>",
        }
    ],
    "compids_dup": <boolean>",
    "csum_calc": "<int>",
    "csum_file": "<int>",
    "csum_valid": <boolean>",
    "err": <int>",
    "offset": <int>",
}
```

## Usage

Build and start the docker container using the included Dockerfile. Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.
