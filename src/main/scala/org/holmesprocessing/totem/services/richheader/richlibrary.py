#!/usr/bin/env python3

import sys, struct

class MZSignatureError(Exception):
    pass

class PESignatureError(Exception):
    pass

class RichSignatureError(Exception):
    pass

class DanSSignatureError(Exception):
    pass

class PaddingError(Exception):
    pass

class RichLengthError(Exception):
    pass

class FileReadError(Exception):
    pass

def err2str(code):
    return{
        -2: "MZ signature not found",
        -3: "PE signature not found",
        -4: "Rich signature not found. This file probably has no Rich header.",
        -5: "DanS signature not found. Rich header corrupt.",
        -6: "Wrong header padding behind DanS signature. Rich header corrupt.",
        -7: "Rich data length not a multiple of 8. Rich header corrupt.",
        }[code]

class RichLibrary:

    def __u32(self, x):
        return struct.unpack("<I", x)[0]

    def __p32(self, x):
        return struct.pack("<I", x)

    def __rol32(self, v, n):
        return ((v << (n & 0x1f)) & 0xffffffff) | (v >> (32 - (n & 0x1f)))

    def csum(self, raw_dat, compids, off):
        csum = off

        for i in range(off):
            ## Mask out the e_lfanew field as it's not initialized yet
            if i in range(0x3c, 0x40):
                continue
            csum += self.__rol32(raw_dat[i], i)

        for c in compids:
            csum += self.__rol32(c['pid'] << 16 | c['mcv'], c['cnt'])

        ## Truncate calculated checksum to 32 bit
        return csum & 0xffffffff

    def parse(self):
        dat = open(self.fname, 'rb').read()

        ## Do basic sanity checks on the PE
        if dat[0:][:2] != b'MZ':
            raise MZSignatureError()

        e_lfanew = self.__u32(dat[0x3c:][:4])
        if dat[e_lfanew:][:2] != b'PE':
            raise PESignatureError()

        ## IMPORTANT: Do not assume the data to start at 0x80, this is not always
        ## the case (modified DOS stub). Instead, start searching backwards for
        ## 'Rich', stop at beginning of DOS header.
        rich = 0
        for rich in range(e_lfanew, self.SIZE_DOS_HEADER, -1):
            if dat[rich:][:4] == b'Rich':
                break

        if rich == self.SIZE_DOS_HEADER:
            raise RichSignatureError()

        ## We found a valid 'Rich' signature in the header from here on
        csum = self.__u32(dat[rich + 4:][:4])

        ## xor backwards with csum until either 'DanS' or end of the DOS header,
        ## invert the result to get original order
        upack = [ self.__u32(dat[i:][:4]) ^ csum for i in range(rich - 4, self.SIZE_DOS_HEADER, -4) ][::-1]
        if self.__u32(b'DanS') not in upack:
            raise DanSSignatureError()

        upack = upack[upack.index(self.__u32(b'DanS')):]
        dans = e_lfanew - len(upack) * 4 - (e_lfanew - rich)

        ## DanS is _always_ followed by three zero dwords
        if not all([upack[i] == 0 for i in range(1, 4)]):
            raise PaddingError()

        upack = upack[4:]

        if len(upack) & 1:
            raise RichLengthError()

        cmpids = []
        for i in range(0, len(upack), 2):
            cmpids.append({
                'mcv': (upack[i + 0] >>  0) & 0xffff,
                'pid': (upack[i + 0] >> 16) & 0xffff,
                'cnt': (upack[i + 1] >>  0)
            })

        ## Bonus feature: Calculate and check the check sum csum
        chk = self.csum(dat, cmpids, dans)

        return {'error': 0, 'cmpids': cmpids, 'csum_calc': chk, 'csum_file': csum,
                'offset': dans}

    def __pprint_cmpids(self, cmpids):
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

    def pprint_header(self, data):
        self.__pprint_cmpids(data['cmpids'])
        if rich['csum_calc'] == rich['csum_file']:
            print("\x1b[32mChecksums match! (0x{:08x})".format(rich['csum_calc']))
        else:
            print("\x1b[33mChecksum corrupt! (calc 0x{:08x}, file "
            "0x{:08x})".format(rich['csum_calc'], rich['csum_file']))
        print("\x1b[39m" + "-" * (20 + 16 + 16))

    def __init__(self, path):
        self.data = {}
        self.SIZE_DOS_HEADER = 0x40

        self.fname = path
