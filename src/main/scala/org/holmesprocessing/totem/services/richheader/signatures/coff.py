#!/usr/bin/env python3

## Definitions and helper functions for COFF object files

def storage_class(n):
    if n == 0:
        return "None"
    elif n == 1:
        return "Automatic (Stack)"
    elif n == 2:
        return "Extern"
    elif n == 3:
        return "Static"
    elif n == 4:
        return "Register"
    elif n == 101:
        return "Function"

def sec_flags(m):
    res = []
    for i in list(range(0, 20)) + list(range(24,32)):
        n = m & (1 << i)

        if n & 0x8:
            res.append("No Pad")
        elif n & 0x20:
            res.append("Code")
        elif n & 0x40:
            res.append("Initialized Data")
        elif n & 0x80:
            res.append("Uninitialized Data")
        elif n & 0x100:
            res.append("Other")
        elif n & 0x200:
            res.append("Info")
        elif n & 0x800:
            res.append("Remove")
        elif n & 0x1000:
            res.append("COMDAT")
        elif n & 0x4000:
            res.append("No Defer Spec Exc")
        elif n & 0x8000:
            res.append("Short (GP Relative)")
        elif n & 0x20000:
            res.append("Thumb/MIPS16/Purgeable")
        elif n & 0x40000:
            res.append("Locked")
        elif n & 0x80000:
            res.append("Preload")
        elif n & 0x1000000:
            res.append("Extended relocations")
        elif n & 0x2000000:
            res.append("Discardable")
        elif n & 0x4000000:
            res.append("Not Cached")
        elif n & 0x10000000:
            res.append("Shared")
        elif n & 0x20000000:
            res.append("Execute")
        elif n & 0x40000000:
            res.append("Read")
        elif n & 0x80000000:
            res.append("Write")
    if m & 0xf00000:
        res.append("{} byte align".format(int(2**(((m & 0xf00000) >> 20) - 1))))
    else:
        res.append("(no alignment specified)")

    return res

## Translates a relocation value into a string and a relocation size
def reloc_type_i386(n):
    if n == 0:
        return "ABS", 0
    elif n == 1:
        return "DIR16", 16
    elif n == 2:
        return "REL16", 16
    elif n == 6:
        return "DIR32", 32
    elif n == 7:
        return "DIR32NB", 32   ## NB = No Base = RVA
    elif n == 9:
        return "SEG12", 12     ## 12 bit segment index
    elif n == 10:
        return "SECTION", 16   ## 16 bit section index
    elif n == 11:
        return "SECREL", 32    ## section relative
    elif n == 12:
        return "TOKEN", 32     ## CLR token
    elif n == 13:
        return "SECREL7", 7
    elif n == 20:
        return "REL32", 32
    else:
        return "UNK ({})".format(n)

def reloc_type_amd64(n):
    if n == 0:
        return "ABS", 0
    elif n == 1:
        return "DIR64", 64
    elif n == 2:
        return "DIR32", 32
    elif n == 3:
        return "DIR32NB", 32
    elif n == 4:
        return "REL32", 32
    elif n == 5:
        return "REL32_1", 32
    elif n == 6:
        return "REL32_2", 32
    elif n == 7:
        return "REL32_3", 32
    elif n == 8:
        return "REL32_4", 32
    elif n == 9:
        return "REL32_5", 32
    elif n == 10:
        return "SECTION", 16
    elif n == 11:
        return "SECREL", 16
    elif n == 12:
        return "SECREL7", 16
    elif n == 13:
        return "TOKEN", 16
    elif n == 14:
        return "SREL32", 16
    elif n == 15:
        return "PAIR", 16
    elif n == 16:
        return "SSPAN32", 16
    else:
        return "UNK ({})".format(n)
