# zipmeta service for Holmes-Totem

## Description

This service extracts metadata from a zipfile.


## Output

```json
{
    "__MACOSX/._Screen Shot 2017-09-08 at 10.56.43 AM.png": {
        "InternalAttributes": "None",
        "Name": "UnknownHeader",
        "ZipFileName": "__MACOSX/._Screen Shot 2017-09-08 at 10.56.43 AM.png",
        "ZipUncompressedSize": "120",
        "FileStartDisk": "0",
        "ZipCompressedSize": "50",
        "ZipComments": "None",
        "BlockTag": "b'5558'",
        "VersionMadeBy": "None",
        "ZipRequiredVersion": "2.0",
        "RelativeOffset": "191325",
        "CSize": "12",
        "Data": "Data",
        "ZipCRC": "b'5c300f34'",
        "ExternalAttributes": "2175025152",
        "ZipCompression": "Deflated",
        "ZipModifyDate": "September 08, 2017 10:56:46.000000",
        "ZipBitFlag": "Data Descriptor"
    },
    "__MACOSX/": {
        "InternalAttributes": "None",
        "Name": "UnknownHeader",
        "ZipFileName": "__MACOSX/",
        "ZipUncompressedSize": "0",
        "FileStartDisk": "0",
        "ZipCompressedSize": "0",
        "ZipComments": "None",
        "BlockTag": "b'5558'",
        "VersionMadeBy": "None",
        "ZipRequiredVersion": "1.0",
        "RelativeOffset": "191270",
        "CSize": "12",
        "Data": "Data",
        "ZipCRC": "b'00000000'",
        "ExternalAttributes": "1107116032",
        "ZipCompression": "No Compression/Stored",
        "ZipModifyDate": "September 08, 2017 11:24:58.000000",
        "ZipBitFlag": "None"
    },
    "Screen Shot 2017-09-08 at 10.56.43 AM.png": {
        "InternalAttributes": "None",
        "Name": "UnknownHeader",
        "ZipFileName": "Screen Shot 2017-09-08 at 10.56.43 AM.png",
        "ZipUncompressedSize": "191221",
        "FileStartDisk": "0",
        "ZipCompressedSize": "191167",
        "ZipComments": "None",
        "BlockTag": "b'5558'",
        "VersionMadeBy": "None",
        "ZipRequiredVersion": "2.0",
        "RelativeOffset": "0",
        "CSize": "12",
        "Data": "Data",
        "ZipCRC": "b'3123e044'",
        "ExternalAttributes": "2175025152",
        "ZipCompression": "Deflated",
        "ZipModifyDate": "September 08, 2017 10:56:46.000000",
        "ZipBitFlag": "Data Descriptor"
    },
    "filecount": 3
}
```

## Usage

Build and start the docker container using the included Dockerfile. Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.
