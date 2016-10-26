#!/usr/bin/env python3

import sys, struct

SIZE_DOS_HEADER = 0x40

u32 = lambda x: struct.unpack("<I", x)[0]
p32 = lambda x: struct.pack("<I", x)
rol32 = lambda v, n: ((v << (n & 0x1f)) & 0xffffffff) | (v >> (32 - (n & 0x1f)))

def parse(fname):

    dat = open(fname, 'rb').read()

    ## Do basic sanity checks on the PE
    if dat[0:][:2] != b'MZ':
        return {'err': -2}

    e_lfanew = u32(dat[0x3c:][:4])
    if dat[e_lfanew:][:2] != b'PE':
        return {'err': -3}

    ## IMPORTANT: Do not assume the data to start at 0x80, this is not always
    ## the case (modified DOS stub). Instead, start searching backwards for
    ## 'Rich', stop at beginning of DOS header.
    rich = 0
    for rich in range(e_lfanew, SIZE_DOS_HEADER, -1):
        if dat[rich:][:4] == b'Rich':
            break

    if rich == SIZE_DOS_HEADER:
        return {'err': -4}

    ## We found a valid 'Rich' signature in the header from here on
    csum = u32(dat[rich + 4:][:4])

    ## xor backwards with csum until either 'DanS' or end of the DOS header,
    ## invert the result to get original order
    upack = [ u32(dat[i:][:4]) ^ csum for i in range(rich - 4, SIZE_DOS_HEADER, -4) ][::-1]
    if u32(b'DanS') not in upack:
        return {'err:': -5}

    upack = upack[upack.index(u32(b'DanS')):]
    dans = e_lfanew - len(upack) * 4 - (e_lfanew - rich)

    ## DanS is _always_ followed by three zero dwords
    if not all([upack[i] == 0 for i in range(1, 4)]):
        return {'err': -6}

    upack = upack[4:]

    if len(upack) & 1:
        return {'err': -7}

    cmpids = []

    ## Bonus feature: Calculate and check the check sum csum
    chk = dans
    for i in range(dans):
        ## Mask out the e_lfanew field as it's not initialized yet
        if i in range(0x3c, 0x40):
            continue
        chk += rol32(dat[i], i)

    for i in range(0, len(upack), 2):
        cmpids.append({
            'mcv': (upack[i + 0] >>  0) & 0xffff,
            'pid': (upack[i + 0] >> 16) & 0xffff,
            'cnt': (upack[i + 1] >>  0)
        })
        ## Exclude the "generic file" descriptor from the check sum
        #if cmpids[-1]['mcv'] & 0xffff != 0:
        chk += rol32(upack[i + 0], upack[i + 1])

    ## Truncate calculated checksum to 32 bit
    chk &= 0xffffffff

    return {'err': 0, 'cmpids': cmpids, 'csum_calc': chk, 'csum_file': csum,
            'offset': dans}

def err2str(code):
    if code == -2:
        return "MZ signature not found"
    elif code == -3:
        return "PE signature not found"
    elif code == -4:
        return "Rich signature not found. This file probably has no Rich header."
    elif code == -5:
        return "DanS signature not found. Rich header corrupt."
    elif code == -6:
        return "Wrong header padding behind DanS signature. Rich header corrupt."
    elif code == -7:
        return "Rich data length not a multiple of 8. Rich header corrupt."
    else:
        return "--- NO ERROR DESCRIPTION ---"

def pprint_cmpids(cmpids):
    print("-" * (20 + 16 + 16))
    print("{:>20s}{:>16s}{:>16s}".format("Compiler Version", "Product ID",
        "Count"))
    print("-" * (20 + 16 + 16))

    for e in cmpids:
        print("{:>20s}{:>16s}{:>16s}".format(
            "{:5d}".format(e['mcv']),
            "0x{:04x}".format(e['pid']),
            "0x{:08x}".format(e['cnt'])))
    print("-" * (20 + 16 + 16))

def pprint_header(data):
    pprint_cmpids(data['cmpids'])
    if rich['csum_calc'] == rich['csum_file']:
        print("\x1b[32mChecksums match! (0x{:08x})".format(rich['csum_calc']))
    else:
        print("\x1b[33mChecksum corrupt! (calc 0x{:08x}, file "
        "0x{:08x})".format(rich['csum_calc'], rich['csum_file']))
    print("\x1b[39m" + "-" * (20 + 16 + 16))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: {} <pe-file.exe>".format(sys.argv[0]))
        sys.exit(-1)
    rich = parse(sys.argv[1])
    if rich['err'] < 0:
        print("\x1b[33m[-] " + err2str(rich['err']) + "\x1b[39m")
        sys.exit(rich['err'])

    pprint_header(rich)
