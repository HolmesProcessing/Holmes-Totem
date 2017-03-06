# Pdfparse service for Holmes-Totem

## Description

A simple service that parses the pdf file. This service explores the structure of the pdf file and dumps the object content into JSON format.

### Output
```json
results = {
	"Comments": <int>,
	"XREF": <int>,
	"Trailer": <int>,
	"StartXref": <int>,
	"IndirectObject": <int>
}
```

## Usage

Build and start the docker container using the included Dockerfile. Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.
