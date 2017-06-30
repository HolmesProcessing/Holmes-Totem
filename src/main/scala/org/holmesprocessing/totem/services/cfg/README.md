# CFG service for Holmes-Totem

## Description

A simple service that utilizes the open-source library 'nucleus' to retrieve the control flow graph (CFG) from a binary. This service dumps the CFG into JSON format.

### Output
```json
results = {
	"truncated": <boolean>,
	"arcs": {
		[
		"tail":  <string>,
		"head":  <string>,
		"label": <string>
		]
		...
	}
}
```

## Usage

Build and start the docker container using the included Dockerfile. Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.
