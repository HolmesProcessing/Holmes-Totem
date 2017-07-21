# PEInfo 2.0 service for Holmes-Totem

## Description

This service extracts meta information contained in PE binary files. Currently the work is based on the implemention of [pefile](https://github.com/erocarrera/pefile).

you can see the final analysis results [here](#output).

## Usage

Build and start the docker container using the included Dockerfile. Since this container needs to have access to the sample file, you need to run this container with:

`-v /tmp:/tmp:ro`

This allows the container to access /tmp on the local file system in read-only mode.

## Output

```json
{
    "HEADERS": {
        "DOS_HEADER": {
            "Structure": "IMAGE_DOS_HEADER",
            "e_magic": {
                "FileOffset": 0,
                "Offset": 0,
                "Value": 23117
            },
            "e_cblp": {
                "FileOffset": 2,
                "Offset": 2,
                "Value": 144
            },
            "e_cp": {
                "FileOffset": 4,
                "Offset": 4,
                "Value": 3
            },
            "e_crlc": {
                "FileOffset": 6,
                "Offset": 6,
                "Value": 0
            },
            "e_cparhdr": {
                "FileOffset": 8,
                "Offset": 8,
                "Value": 4
            },
            "e_minalloc": {
                "FileOffset": 10,
                "Offset": 10,
                "Value": 0
            },
            "e_maxalloc": {
                "FileOffset": 12,
                "Offset": 12,
                "Value": 65535
            },
            "e_ss": {
                "FileOffset": 14,
                "Offset": 14,
                "Value": 0
            },
            "e_sp": {
                "FileOffset": 16,
                "Offset": 16,
                "Value": 184
            },
            "e_csum": {
                "FileOffset": 18,
                "Offset": 18,
                "Value": 0
            },
            "e_ip": {
                "FileOffset": 20,
                "Offset": 20,
                "Value": 0
            },
            "e_cs": {
                "FileOffset": 22,
                "Offset": 22,
                "Value": 0
            },
            "e_lfarlc": {
                "FileOffset": 24,
                "Offset": 24,
                "Value": 64
            },
            "e_ovno": {
                "FileOffset": 26,
                "Offset": 26,
                "Value": 0
            },
            "e_res": {
                "FileOffset": 28,
                "Offset": 28,
                "Value": ""
            },
            "e_oemid": {
                "FileOffset": 36,
                "Offset": 36,
                "Value": 0
            },
            "e_oeminfo": {
                "FileOffset": 38,
                "Offset": 38,
                "Value": 0
            },
            "e_res2": {
                "FileOffset": 40,
                "Offset": 40,
                "Value": ""
            },
            "e_lfanew": {
                "FileOffset": 60,
                "Offset": 60,
                "Value": 200
            }
        },
        "NT_HEADERS": {
            "Structure": "IMAGE_NT_HEADERS",
            "Signature": {
                "FileOffset": 200,
                "Offset": 0,
                "Value": 17744
            }
        },
        "FILE_HEADER": {
            "Structure": "IMAGE_FILE_HEADER",
            "Machine": {
                "FileOffset": 204,
                "Offset": 0,
                "Value": 332
            },
            "NumberOfSections": {
                "FileOffset": 206,
                "Offset": 2,
                "Value": 5
            },
            "TimeDateStamp": {
                "FileOffset": 208,
                "Offset": 4,
                "Value": "0x38FDEF5D [Wed Apr 19 17:39:41 2000 UTC]"
            },
            "PointerToSymbolTable": {
                "FileOffset": 212,
                "Offset": 8,
                "Value": 0
            },
            "NumberOfSymbols": {
                "FileOffset": 216,
                "Offset": 12,
                "Value": 0
            },
            "SizeOfOptionalHeader": {
                "FileOffset": 220,
                "Offset": 16,
                "Value": 224
            },
            "Characteristics": {
                "FileOffset": 222,
                "Offset": 18,
                "Value": 271
            }
        },
        "OPTIONAL_HEADER": {
            "Structure": "IMAGE_OPTIONAL_HEADER",
            "Magic": {
                "FileOffset": 224,
                "Offset": 0,
                "Value": 267
            },
            "MajorLinkerVersion": {
                "FileOffset": 226,
                "Offset": 2,
                "Value": 5
            },
            "MinorLinkerVersion": {
                "FileOffset": 227,
                "Offset": 3,
                "Value": 10
            },
            "SizeOfCode": {
                "FileOffset": 228,
                "Offset": 4,
                "Value": 20992
            },
            "SizeOfInitializedData": {
                "FileOffset": 232,
                "Offset": 8,
                "Value": 18944
            },
            "SizeOfUninitializedData": {
                "FileOffset": 236,
                "Offset": 12,
                "Value": 0
            },
            "AddressOfEntryPoint": {
                "FileOffset": 240,
                "Offset": 16,
                "Value": 14584
            },
            "BaseOfCode": {
                "FileOffset": 244,
                "Offset": 20,
                "Value": 4096
            },
            "BaseOfData": {
                "FileOffset": 248,
                "Offset": 24,
                "Value": 28672
            },
            "ImageBase": {
                "FileOffset": 252,
                "Offset": 28,
                "Value": 4194304
            },
            "SectionAlignment": {
                "FileOffset": 256,
                "Offset": 32,
                "Value": 4096
            },
            "FileAlignment": {
                "FileOffset": 260,
                "Offset": 36,
                "Value": 512
            },
            "MajorOperatingSystemVersion": {
                "FileOffset": 264,
                "Offset": 40,
                "Value": 4
            },
            "MinorOperatingSystemVersion": {
                "FileOffset": 266,
                "Offset": 42,
                "Value": 0
            },
            "MajorImageVersion": {
                "FileOffset": 268,
                "Offset": 44,
                "Value": 0
            },
            "MinorImageVersion": {
                "FileOffset": 270,
                "Offset": 46,
                "Value": 0
            },
            "MajorSubsystemVersion": {
                "FileOffset": 272,
                "Offset": 48,
                "Value": 4
            },
            "MinorSubsystemVersion": {
                "FileOffset": 274,
                "Offset": 50,
                "Value": 0
            },
            "Reserved1": {
                "FileOffset": 276,
                "Offset": 52,
                "Value": 0
            },
            "SizeOfImage": {
                "FileOffset": 280,
                "Offset": 56,
                "Value": 139264
            },
            "SizeOfHeaders": {
                "FileOffset": 284,
                "Offset": 60,
                "Value": 1024
            },
            "CheckSum": {
                "FileOffset": 288,
                "Offset": 64,
                "Value": 152262
            },
            "Subsystem": {
                "FileOffset": 292,
                "Offset": 68,
                "Value": 2
            },
            "DllCharacteristics": {
                "FileOffset": 294,
                "Offset": 70,
                "Value": 0
            },
            "SizeOfStackReserve": {
                "FileOffset": 296,
                "Offset": 72,
                "Value": 32000
            },
            "SizeOfStackCommit": {
                "FileOffset": 300,
                "Offset": 76,
                "Value": 4096
            },
            "SizeOfHeapReserve": {
                "FileOffset": 304,
                "Offset": 80,
                "Value": 32000
            },
            "SizeOfHeapCommit": {
                "FileOffset": 308,
                "Offset": 84,
                "Value": 4096
            },
            "LoaderFlags": {
                "FileOffset": 312,
                "Offset": 88,
                "Value": 0
            },
            "NumberOfRvaAndSizes": {
                "FileOffset": 316,
                "Offset": 92,
                "Value": 16
            }
        }
    },
    "Sections": [
        {
            "Structure": "IMAGE_SECTION_HEADER",
            "Name": {
                "FileOffset": 448,
                "Offset": 0,
                "Value": ".text\\x00\\x00\\x00"
            },
            "Misc": {
                "FileOffset": 456,
                "Offset": 8,
                "Value": 20502
            },
            "Misc_PhysicalAddress": {
                "FileOffset": 456,
                "Offset": 8,
                "Value": 20502
            },
            "Misc_VirtualSize": {
                "FileOffset": 456,
                "Offset": 8,
                "Value": 20502
            },
            "VirtualAddress": {
                "FileOffset": 460,
                "Offset": 12,
                "Value": 4096
            },
            "SizeOfRawData": {
                "FileOffset": 464,
                "Offset": 16,
                "Value": 20992
            },
            "PointerToRawData": {
                "FileOffset": 468,
                "Offset": 20,
                "Value": 1024
            },
            "PointerToRelocations": {
                "FileOffset": 472,
                "Offset": 24,
                "Value": 0
            },
            "PointerToLinenumbers": {
                "FileOffset": 476,
                "Offset": 28,
                "Value": 0
            },
            "NumberOfRelocations": {
                "FileOffset": 480,
                "Offset": 32,
                "Value": 0
            },
            "NumberOfLinenumbers": {
                "FileOffset": 482,
                "Offset": 34,
                "Value": 0
            },
            "Characteristics": {
                "FileOffset": 484,
                "Offset": 36,
                "Value": 1610612768
            },
            "entrophy": 6.449003422775913,
            "md5": "ed6b47a15e5bd168e28a19611e25969d",
            "SHA-1": "9d3d9ff777c8c97010c2271af1f06cc134b94566",
            "SHA-256": "6204f9da901a083af9c446ec2a84f61728d0fd7944f8605758299a22ceb2ae7d",
            "SHA-512": "bf29af186073f7b7e1ff971df310d739bfafbb59ad8bb5bf9715ca298aec189ffcc5ed7b1626d645a8bbf1ae84cabe17b0b01cf283f4efd1930c0b3a0bafa55c"
        },
    ],
    "Directories": [
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_EXPORT",
            "VirtualAddress": {
                "FileOffset": 320,
                "Offset": 0,
                "Value": 31344
            },
            "Size": {
                "FileOffset": 324,
                "Offset": 4,
                "Value": 50
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_IMPORT",
            "VirtualAddress": {
                "FileOffset": 328,
                "Offset": 0,
                "Value": 29116
            },
            "Size": {
                "FileOffset": 332,
                "Offset": 4,
                "Value": 120
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_RESOURCE",
            "VirtualAddress": {
                "FileOffset": 336,
                "Offset": 0,
                "Value": 49152
            },
            "Size": {
                "FileOffset": 340,
                "Offset": 4,
                "Value": 1288
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
            "VirtualAddress": {
                "FileOffset": 344,
                "Offset": 0,
                "Value": 0
            },
            "Size": {
                "FileOffset": 348,
                "Offset": 4,
                "Value": 0
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_SECURITY",
            "VirtualAddress": {
                "FileOffset": 352,
                "Offset": 0,
                "Value": 120832
            },
            "Size": {
                "FileOffset": 356,
                "Offset": 4,
                "Value": 6776
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_BASERELOC",
            "VirtualAddress": {
                "FileOffset": 360,
                "Offset": 0,
                "Value": 0
            },
            "Size": {
                "FileOffset": 364,
                "Offset": 4,
                "Value": 0
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_DEBUG",
            "VirtualAddress": {
                "FileOffset": 368,
                "Offset": 0,
                "Value": 0
            },
            "Size": {
                "FileOffset": 372,
                "Offset": 4,
                "Value": 0
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_COPYRIGHT",
            "VirtualAddress": {
                "FileOffset": 376,
                "Offset": 0,
                "Value": 0
            },
            "Size": {
                "FileOffset": 380,
                "Offset": 4,
                "Value": 0
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
            "VirtualAddress": {
                "FileOffset": 384,
                "Offset": 0,
                "Value": 0
            },
            "Size": {
                "FileOffset": 388,
                "Offset": 4,
                "Value": 0
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_TLS",
            "VirtualAddress": {
                "FileOffset": 392,
                "Offset": 0,
                "Value": 0
            },
            "Size": {
                "FileOffset": 396,
                "Offset": 4,
                "Value": 0
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
            "VirtualAddress": {
                "FileOffset": 400,
                "Offset": 0,
                "Value": 0
            },
            "Size": {
                "FileOffset": 404,
                "Offset": 4,
                "Value": 0
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
            "VirtualAddress": {
                "FileOffset": 408,
                "Offset": 0,
                "Value": 0
            },
            "Size": {
                "FileOffset": 412,
                "Offset": 4,
                "Value": 0
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_IAT",
            "VirtualAddress": {
                "FileOffset": 416,
                "Offset": 0,
                "Value": 28672
            },
            "Size": {
                "FileOffset": 420,
                "Offset": 4,
                "Value": 428
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
            "VirtualAddress": {
                "FileOffset": 424,
                "Offset": 0,
                "Value": 0
            },
            "Size": {
                "FileOffset": 428,
                "Offset": 4,
                "Value": 0
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
            "VirtualAddress": {
                "FileOffset": 432,
                "Offset": 0,
                "Value": 0
            },
            "Size": {
                "FileOffset": 436,
                "Offset": 4,
                "Value": 0
            }
        },
        {
            "Structure": "IMAGE_DIRECTORY_ENTRY_RESERVED",
            "VirtualAddress": {
                "FileOffset": 440,
                "Offset": 0,
                "Value": 0
            },
            "Size": {
                "FileOffset": 444,
                "Offset": 4,
                "Value": 0
            }
        }
    ],
	"VersionInfo": {},
    "Exports": [
        {
            "Structure": "IMAGE_EXPORT_DIRECTORY",
            "Characteristics": {
                "FileOffset": 24688,
                "Offset": 0,
                "Value": 0
            },
            "TimeDateStamp": {
                "FileOffset": 24692,
                "Offset": 4,
                "Value": "0x38FDEF5D [Wed Apr 19 17:39:41 2000 UTC]"
            },
            "MajorVersion": {
                "FileOffset": 24696,
                "Offset": 8,
                "Value": 0
            },
            "MinorVersion": {
                "FileOffset": 24698,
                "Offset": 10,
                "Value": 0
            },
            "Name": {
                "FileOffset": 24700,
                "Offset": 12,
                "Value": 31384
            },
            "Base": {
                "FileOffset": 24704,
                "Offset": 16,
                "Value": 1
            },
            "NumberOfFunctions": {
                "FileOffset": 24708,
                "Offset": 20,
                "Value": 0
            },
            "NumberOfNames": {
                "FileOffset": 24712,
                "Offset": 24,
                "Value": 0
            },
            "AddressOfFunctions": {
                "FileOffset": 24716,
                "Offset": 28,
                "Value": 31384
            },
            "AddressOfNames": {
                "FileOffset": 24720,
                "Offset": 32,
                "Value": 31384
            },
            "AddressOfNameOrdinals": {
                "FileOffset": 24724,
                "Offset": 36,
                "Value": 31384
            }
        }
    ],
    "Importedsymbols": [
        [
            {
                "Structure": "IMAGE_IMPORT_DESCRIPTOR",
                "OriginalFirstThunk": {
                    "FileOffset": 22460,
                    "Offset": 0,
                    "Value": 29480
                },
                "Characteristics": {
                    "FileOffset": 22460,
                    "Offset": 0,
                    "Value": 29480
                },
                "TimeDateStamp": {
                    "FileOffset": 22464,
                    "Offset": 4,
                    "Value": "0x0        [Thu Jan  1 00:00:00 1970 UTC]"
                },
                "ForwarderChain": {
                    "FileOffset": 22468,
                    "Offset": 8,
                    "Value": 0
                },
                "Name": {
                    "FileOffset": 22472,
                    "Offset": 12,
                    "Value": 29698
                },
                "FirstThunk": {
                    "FileOffset": 22476,
                    "Offset": 16,
                    "Value": 28916
                }
            }
        ]
    ],
	"BoundImports": {},
	"DelayImportedSymbols": {},
    "ResourceDirectory": [
        {
            "Structure": "IMAGE_RESOURCE_DIRECTORY",
            "Characteristics": {
                "FileOffset": 36864,
                "Offset": 0,
                "Value": 0
            },
            "TimeDateStamp": {
                "FileOffset": 36868,
                "Offset": 4,
                "Value": "0x0        [Thu Jan  1 00:00:00 1970 UTC]"
            },
            "MajorVersion": {
                "FileOffset": 36872,
                "Offset": 8,
                "Value": 0
            },
            "MinorVersion": {
                "FileOffset": 36874,
                "Offset": 10,
                "Value": 0
            },
            "NumberOfNamedEntries": {
                "FileOffset": 36876,
                "Offset": 12,
                "Value": 0
            },
            "NumberOfIdEntries": {
                "FileOffset": 36878,
                "Offset": 14,
                "Value": 2
            }
        },
        {
            "Id": [
                3,
                "RT_ICON"
            ],
            "Structure": "IMAGE_RESOURCE_DIRECTORY_ENTRY",
            "Name": {
                "FileOffset": 36880,
                "Offset": 0,
                "Value": 3
            },
            "OffsetToData": {
                "FileOffset": 36884,
                "Offset": 4,
                "Value": 2147483680
            }
        },
        [
            {
                "Structure": "IMAGE_RESOURCE_DIRECTORY",
                "Characteristics": {
                    "FileOffset": 36896,
                    "Offset": 0,
                    "Value": 0
                },
                "TimeDateStamp": {
                    "FileOffset": 36900,
                    "Offset": 4,
                    "Value": "0x0        [Thu Jan  1 00:00:00 1970 UTC]"
                },
                "MajorVersion": {
                    "FileOffset": 36904,
                    "Offset": 8,
                    "Value": 0
                },
                "MinorVersion": {
                    "FileOffset": 36906,
                    "Offset": 10,
                    "Value": 0
                },
                "NumberOfNamedEntries": {
                    "FileOffset": 36908,
                    "Offset": 12,
                    "Value": 0
                },
                "NumberOfIdEntries": {
                    "FileOffset": 36910,
                    "Offset": 14,
                    "Value": 2
                }
            },
            {
                "Id": 1,
                "Structure": "IMAGE_RESOURCE_DIRECTORY_ENTRY",
                "Name": {
                    "FileOffset": 36912,
                    "Offset": 0,
                    "Value": 1
                },
                "OffsetToData": {
                    "FileOffset": 36916,
                    "Offset": 4,
                    "Value": 2147483736
                }
            },
            [
                {
                    "Structure": "IMAGE_RESOURCE_DIRECTORY",
                    "Characteristics": {
                        "FileOffset": 36952,
                        "Offset": 0,
                        "Value": 0
                    },
                    "TimeDateStamp": {
                        "FileOffset": 36956,
                        "Offset": 4,
                        "Value": "0x0        [Thu Jan  1 00:00:00 1970 UTC]"
                    },
                    "MajorVersion": {
                        "FileOffset": 36960,
                        "Offset": 8,
                        "Value": 0
                    },
                    "MinorVersion": {
                        "FileOffset": 36962,
                        "Offset": 10,
                        "Value": 0
                    },
                    "NumberOfNamedEntries": {
                        "FileOffset": 36964,
                        "Offset": 12,
                        "Value": 0
                    },
                    "NumberOfIdEntries": {
                        "FileOffset": 36966,
                        "Offset": 14,
                        "Value": 1
                    }
                },
                {
                    "LANG": 9,
                    "SUBLANG": 1,
                    "LANG_NAME": "LANG_ENGLISH",
                    "SUBLANG_NAME": "SUBLANG_ENGLISH_US",
                    "Structure": "IMAGE_RESOURCE_DATA_ENTRY",
                    "Name": {
                        "FileOffset": 36968,
                        "Offset": 0,
                        "Value": 1033
                    },
                    "OffsetToData": {
                        "FileOffset": 37024,
                        "Offset": 0,
                        "Value": 49360
                    },
                    "Size": {
                        "FileOffset": 37028,
                        "Offset": 4,
                        "Value": 744
                    },
                    "CodePage": {
                        "FileOffset": 37032,
                        "Offset": 8,
                        "Value": 0
                    },
                    "Reserved": {
                        "FileOffset": 37036,
                        "Offset": 12,
                        "Value": 0
                    }
                }
            ],    
        ]
    ]
}

```
