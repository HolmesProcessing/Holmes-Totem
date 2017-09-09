# PEMETA service for Holmes-Totem

## Description

This service requires basic understanding of the layout of PE file. This service extracts meta information about a Windows Portable Executable file. The analyser library used in PEV's [libpe](https://github.com/merces/libpe). PEV is PE file analysis toolkit. Its feature rich, fast and is written C Programing langauge. This pemeta services wraps all the features of PEV's libpe using golang's cgo.

## Performance Comparison

| sha2 (last 8 chars) | Name | PEMETA | PEINFO (v1) | PEINFO (v2) |
| --- | --- | --- | --- | --- |
|c3597767 | umss.exe | 57.7ms | 413.4 ms | 87.2ms |
|bb30af68|EXE.exe| 751.2ms |4340.1ms |832.3ms|
|81faa32e|_isdel.exe |21.6ms |243.4ms |error (exports)|
|56254abc| ccsetup514.exe| 1001.0ms | 6267.8 ms |764.6 ms|
|73da12d8| chkdsk.exe| 21.8ms | 758.3ms |92.9ms|
|9b7dd7e8| cipher.exe |31.4ms |730.3 ms |error|
|084409a0| bfsvc.exe |58.3ms |error |77.1ms|
|ec479399| autoconv.exe |295.4ms |1404.9ms |382.6ms|
|acb8d3da| ARP.exe |  15.8ms |635.1ms |54.8ms|
|44bd81cb|7z1514.exe| 249.04ms |1261.5ms |133.9ms|
|Average||250.1ms|2232.3ms|242.5ms|

### Output

Here is the sample output of pemeta. For further details on the output, please refer to the [official documentation](http://pev.readthedocs.io/projects/libpe/en/latest/) of libpe.

```json
	{
    "Headers": {
        "Optional": {
            "Magic": 267,
            "MajorLinkerVersion": 5,
            "MinorLinkerVersion": 0,
            "SizeOfCode": 1609728,
            "AddressOfEntryPoint": 6156,
            "BaseOfCode": 4096,
            "ImageBase": 4194304,
            "SectionAlignment": 4096,
            "FileAlignment": 512,
            "MajorOperatingSystemVersion": 4,
            "MinorOperatingSystemVersion": 0,
            "MajorImageVersion": 0,
            "MinorImageVersion": 0,
            "MajorSubsystemVersion": 4,
            "MinorSubsystemVersion": 0,
            "Reserved1": 0,
            "SizeOfImage": 2867200,
            "SizeOfHeaders": 1536,
            "CheckSum": 0,
            "Subsystem": 2,
            "DllCharacteristics": 0,
            "SizeOfStackReserve": 1048576,
            "SizeOfStackCommit": 8192,
            "SizeOfHeapReserve": 1048576,
            "SizeOfHeapCommit": 4096,
            "LoaderFlags": 0,
            "NumberOfRvaAndSizes": 16
        },
        "DosHeaders": {
            "e_magic": 23117,
            "e_crlc": 0,
            "e_cparhdr": 4,
            "e_minalloc": 15,
            "e_maxalloc": 65535,
            "e_ss": 0,
            "e_sp": 184,
            "e_csum": 0,
            "e_ip": 0,
            "e_cs": 0,
            "e_lfarlc": 64,
            "e_ovno": 26,
            "e_res": 0,
            "e_oemid": 0,
            "e_oeminfo": 0,
            "e_res2": 0,
            "e_lfanew": 512
        },
        "CoffHeaders": {
            "Machine": "14C",
            "NumberOfSections": "8",
            "TimeDateStamp": "2000-04-19 17:39:41 +0000 UTC",
            "PointerToSymbolTable": "0",
            "NumberOfSymbols": "0",
            "SizeOfOptionalHeader": "E0",
            "Characteristics": "30E"
        }
    },
    "directories": [
        
        {
            "Name": "IMAGE_DIRECTORY_RESERVED",
            "VirtualAddress": "0",
            "Size": 0
        }
    ],
    "directories_count": 16,
    "sections": [
        {
            "Name": ".reloc\u0000\u0000",
            "VirtualAddress": "2A6000",
            "PointerToRawData": "290000",
            "NumberOfRelocations": 0,
            "Characteristics": "2A6000",
            "VirtualSize": 0,
            "SizeOfRawData": 89600
        }
    ],
    "sectionscount": 8,
    "PEHash": {
        "Headers": [
            {
                "Name": "IMAGE_DOS_HEADER",
                "md5": "54db2ef47933875195271517db0da174",
                "sha1": "59f2f44c0d6df8465359958aff23fef97118e6a9",
                "sha256": "4e51005c4ea922fd4f85bbf58b26d793087a1b6b8f29fdeb1761407e5865394d",
                "ssdeep": "3:MpPqt/Vn:Mx2"
            }
        ],
        "Sections": [
            
            {
                "Name": ".reloc",
                "md5": "b7db981289a3526eef8e94c17753acb2",
                "sha1": "59d5592afb6da7298f2086d3deef68ab28836fa4",
                "sha256": "b3a6f96c1d025d705f4470a578630bfef2cdebaad47b5b403870de061f740850",
                "ssdeep": "1536:BPzyqpZ3Axt7inBN1i4iIA2cBrn6Ev00IHEJdWJXbYpfQUXYK8kZVgvE/icEJPi:1zpyt7iB6LIa0XGWJUWK8kZaGicUioD"
            }
        ],
        "PEFile": {
            "Name": "PEfile hash",
            "md5": "1b66134e3491139bb9eb032abda9efc0",
            "sha1": "71bd001116bdc71d336b838b4206b2ba08a31d0f",
            "sha256": "287e051fc76e37286d88530e2e33494b6a9507fd356ed2cc8046b6f9c8ff328a",
            "ssdeep": "49152:7tiTejYz4wu4C3SFHL7/SfQIx3lLwEabyNpWeX/4tz5mW/If6F+/uwEfaeXiGGL:ZclLsmEHaZrzRvCz"
        },
        "Imphash": ""
    },
    "Exports": null,
    "Imports": [
        {
            "DllName": "rtl60.bpl",
            "Functions": [
                "@$xp$14System@TObject",
                "@System@TObject@",
                "@$xp$13System@String",
                "@$xp$14System@Integer",
                "@$xp$14System@Boolean"
            ]
        },
        {
            "DllName": "rtl60.bpl",
            "Functions": [
                "@Types@initialization$qqrv",
                "@Types@Finalization$qqrv",
                "@Types@IsRectEmpty$qqrrx11Types@TRect"
            ]
        }
        
    ],
    "resources": {
        "RESOURCE_DIRECTORY": [
            {
                "NodeType": 3,
                "Characteristics": 0,
                "TimeDateStamp": 1049598396,
                "MajorVersion": 0,
                "MinorVersion": 0,
                "NumberOfNamedEntries": 0,
                "NumberOfIdEntries": 1
            }
        ],
        "DIRECTORY_ENTRY": [
            {
                "NodeType": 3,
                "NameOffset": 1049,
                "NameIsString": 0,
                "OffsetIsDirectory": 2688,
                "DataIsDirectory": 0
            }
        ],
        "DATA_STRING": [
            {
                "NodeType": 3,
                "Strlen": 0,
                "String": 24576
            }
        ],
        "DATA_ENTRY": [
            {
                "NodeType": 3,
                "OffsetToData": 2774036,
                "Size": 561,
                "CodePage": 0,
                "Reserved": 0
            }
        ]
    },
    "Entrophy": 6.1526246,
    "FPUtrick": true,
    "CPLAnalysis": -1,
    "CheckFakeEntrypoint": 0
}
```

## Usage

### Building
Build and start the docker container using the included Dockerfile. Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.

### `FPU Trick`
This functionality gives information about undocumented anti-disassembly fpu trick detection. Basically This feature finds of if there is any analysis avoidance techniquesused with that PE File.

This value for this key will be `true` if PEV detects fpu tricks. And returns `false` if there are not such trick used. 

### `CPLAnalysis`
For this PEV's [cpload](http://pev.sourceforge.net/doc/manual/en_us/ch06.html#cpload) tool is used.

The feature tells details about `.cpl` format files.
**Output Details:**
-1 -> Not a DLL
0 -> no threat
1 -> This could be a potential malware

### `CheckFakeEntrypoint`
This feature check if there the entry point is fake. Checks if we are able to get Sections form the AddressOfEntryPoint. If we able to get, then it returns Normal (0) otherwise it returns fake (-1)
0 -> Normal
1 -> Fake
