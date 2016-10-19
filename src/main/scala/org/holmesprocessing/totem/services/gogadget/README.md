# GoGadget service for Holmes-Totem

## Description

A simple service to extract the ROP Gadgets of a binary file.

### Output
```json
results = {
	"total_unique_gadgets": "<int>",
	"total_gadgets_recorded": "<int>",
	"truncated": "<boolean>",
	"search_depth": "<int>",
	"gadgets": {
		"offset": "<hex>",
		"instructions": [
			"(opcodes)",
			"(opcodes)",
		],
	},
}
```

## Usage

Build and start the docker container using the included Dockerfile. Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.
