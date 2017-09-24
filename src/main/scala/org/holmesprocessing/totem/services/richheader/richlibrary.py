#!/usr/bin/env python3
import sys, struct, pickle, os
from collections import defaultdict
from multiprocessing import Process, Queue

import pefile

#rich-header
class FileSizeError(Exception):
    pass

class MZSignatureError(Exception):
    pass

class MZPointerError(Exception):
    pass

class PESignatureError(Exception):
    pass

class RichSignatureError(Exception):
    pass

class DanSSignatureError(Exception):
    pass

class HeaderPaddingError(Exception):
    pass

class RichLengthError(Exception):
    pass

class ProdIDError(Exception):
    pass

#rich-functions
class MachineVersionError(Exception):
    pass

class NoMatchingSignatures(Exception):
    pass

class UnknownRelocationError(Exception):
    pass

HAVE_PIDS = True

try:
    import prodids
except:
    print("[.] Could not find product ID database.")
    HAVE_PIDS = False
    raise ProdIDError()

def err2str(code):
    return{
        -1: "Could not open file.",
        -2: "File too small to contain required headers.",
        -3: "MZ signature not found.",
        -4: "MZ Header pointing beyond end of file.",
        -5: "PE signature not found",
        -6: "Rich signature not found. This file probably has no Rich header.",
        -7: "DanS signature not found. Rich header corrupt.",
        -8: "Wrong header padding behind DanS signature. Rich header corrupt.",
        -9: "Rich data length not a multiple of 8. Rich header corrupt.",
        -10:"No Product ID Database found.",
        -11: "Non x86 PE File",
        -12: "No usable Signatures found (check ./signatures/richDB.py for generating them)",
        -13: "Unknown / non implemented relocation type found"
        }[code]

class RichLibrary:

    def __u32(self, x):
        return struct.unpack("<I", x)[0]

    def __p32(self, x):
        return struct.pack("<I", x)

    def __rol32(self, v, n):
        return ((v << (n & 0x1f)) & 0xffffffff) | (v >> (32 - (n & 0x1f)))

    def generate_csum(self, raw_dat, compids, off):
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
        dat = bytearray(open(self.fname, 'rb').read()[:0x1000])

        ## Do basic sanity checks on the PE
        dat_len = len(dat)
        if dat_len < self.SIZE_DOS_HEADER:
            raise FileSizeError()

        if dat[0:][:2] != b'MZ':
            raise MZSignatureError()

        e_lfanew = self.__u32(dat[self.POS_E_LFANEW:][:4])

        if e_lfanew + 1 > dat_len:
            raise MZPointerError()

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
            raise HeaderPaddingError()

        upack = upack[4:]

        if len(upack) & 1:
            raise RichLengthError()

        cmpids = []
        for i in range(0, len(upack), 2):
            cmpids.append({
                'mcv': (upack[i + 0] >>  0) & 0xffff,
                'pid': (upack[i + 0] >> 16) & 0xffff,
                'compid': upack[i + 0],
                'cnt': (upack[i + 1] >>  0)
            })

        ## Bonus feature: Calculate and check the check sum csum
        chk = self.generate_csum(dat, cmpids, dans)

        return {'error': 0, 'cmpids': cmpids, 'csum_calc': chk, 'csum_file': csum,
                'offset': dans}

    def __pprint_cmpids(self, cmpids):
        print("-" * (20 + 16 + 16 + 32 + 39))
        print("{:>20s}{:>16s}{:>16s} {:>16s} {:>32s}{:>39s}".format("Compiler Patchlevel", "Product ID", "Lib Comp ID",
            "Count", "MS Internal Name", "Visual Studio Release"))
        print("-" * (20 + 16 + 16 + 32 + 39))

        for e in cmpids:
            if HAVE_PIDS:
                try:
                    int_name = prodids.int_names[e['pid']]
                except:
                    int_name = '<unknown>'
                vs_version = prodids.vs_version(e['pid'])

            print("{:>20s}{:>16s}{:>16s}{:>16s}{:>32s}{:>39s}".format(
                "{:5d}".format(e['mcv']),
                "0x{:04x}".format(e['pid']),
                "0x{0:02x}".format(e['compid']),
                "0x{:08x}".format(e['cnt']),
                "{}".format(int_name),
                "{:18s} ({})".format(*vs_version)))
        print("-" * (20 + 16 + 16 + 32 + 39))

    def pprint_header(self, data):
        self.__pprint_cmpids(data['cmpids'])
        if data['csum_calc'] == data['csum_file']:
            print("\x1b[32mChecksums match! (0x{:08x})".format(data['csum_calc']))
        else:
            print("\x1b[33mChecksum corrupt! (calc 0x{:08x}, file "
            "0x{:08x})".format(data['csum_calc'], data['csum_file']))
        print("\x1b[39m" + "-" * (20 + 16 + 16 + 32 + 39))

    ###
    # Begin "Rich Func Finder" Code
    #
    def __loadPE(self):
        with open(self.fname, "rb") as infile:
            dat = infile.read()

        pe = pefile.PE(self.fname)

        if pe.FILE_HEADER.Machine != 0x14C:
            raise MachineVersionError()

        #calculate virtual Memory layout size / offsets
        codebase = 0
        imagebase = pe.OPTIONAL_HEADER.ImageBase
        for s in pe.sections:
            ## TODO actually check for --x attribute
            if s.Name.strip(b"\x00").decode() == ".text":
                dat = dat[s.PointerToRawData:][:s.SizeOfRawData]
                codebase = s.VirtualAddress
                break

        #range where our functions can be loacted (call targets)
        memranges = [tuple(map(lambda x: x + pe.OPTIONAL_HEADER.ImageBase,
            (s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize))) for s in pe.sections]
        memranges = sorted(memranges, key = lambda mem: mem[0])
        memranges.append((pe.OPTIONAL_HEADER.ImageBase, memranges[0][0]))
        memranges = sorted(memranges, key = lambda mem: mem[0])

        if len(dat) > 1024*1024*4: #4mb will (sadly) take > 5min even with multiple threads
            raise FileSizeError

        return (dat, codebase, imagebase, memranges)

    def __loadHashTable(self):
        hashTable = defaultdict(list)
        loaded = 0
        discarded = 0
        bucketSize = 5
        threshold = 7

        #rich header data
        rich_data = self.parse()

        #load db according to found rich header values
        for cmpid in rich_data['cmpids']:
            if(os.path.isfile("./signatures/" + str(cmpid['compid'])+ ".pickle")):
                with open("./signatures/" + str(cmpid['compid'])+ ".pickle", 'rb') as infile:
                    curr_sig_file = pickle.load(infile)

                    #load signatures into hashtable
                    for sig in curr_sig_file:                   
                        if len(sig['raw']) >= threshold:
                            hashTable[sig['raw'][:bucketSize]].append(sig)
                            loaded += 1
                            self.sigThreshold = max(self.sigThreshold, len(sig['raw'])) #used for multithread overlapping
                        else:
                            discarded += 1

        if loaded == 0:
            raise NoMatchingSignatures()

        return hashTable

    def __split_work(self, work, nr):
        return [work[i::nr] for i in range(nr)]

    #If we find a matching signature in our binary, this can be used to extract all relocations stored for this signature in our db
    def __xtractRelocs(self, sig, dat, virtAddr):

        relocs = sig['relocs']
        syms = sig['syms']
        found_relocs = []

        #Parse all relocations in Signature
        for reloc in relocs:
            reloc_addr = self.__u32(dat[reloc['addr']:reloc['addr']+4]) #extract relocation address ("Call Target")
            name = sig['syms'][reloc['symidx']]['name'] #Name of "Call Target" / Relocation

            if reloc['type'] == 20: #relative relocation to current position
                call_target = virtAddr + reloc['addr'] + 4 + reloc_addr
                if call_target >= 1<<31: 
                    call_target -= 1<<32 #take care of 'negative jumps / offsets'

                if not any([call_target >= r[0] and call_target < r[1] for r in self.memranges]): #is call target in memory range? = no constant
                    continue

                found_relocs.append({'name': name.decode("utf-8"), 'virtAddr': reloc_addr, 
                    'type': reloc['type'], 'call_target': call_target})

            elif reloc['type'] == 6: #direct relocations

                if not any([reloc_addr >= r[0] and reloc_addr < r[1] for r in self.memranges]): #is call target in memory range? = no constant
                    continue

                found_relocs.append({'name': name.decode("utf-8"), 'virtAddr': reloc_addr, 
                    'type': reloc['type'], 'call_target': reloc_addr})

            else:
                raise UnknownRelocationError()

        return found_relocs

    # Worker Process, checking a chunk of the binary with some overlap to other workers
    def search_worker(self, chunk, resQueue, threadid):
        found_dict = {"functions": [], "relocs": []}

        begin = int(max(threadid * len(chunk) - self.sigThreshold*2, 0)) #overlap double the largest signature
        end = int(min((threadid+1) * len(chunk)  + self.sigThreshold*2, len(self.data)))

        while (begin < end - 5):
            #workaround for signatures starting with only 1 to 4 bytes before relocation e.g. 0x424242 + 0x424200 + 0x420000
            currPattern = self.data[begin:begin+5]
            toCheck =   [pattern for pattern in 
                            [currPattern, 
                            bytes([currPattern[0], currPattern[1], currPattern[2], currPattern[3], 0x0]),
                            bytes([currPattern[0], currPattern[1], currPattern[2], 0x0, 0x0]),
                            bytes([currPattern[0], currPattern[1], 0x0, 0x0, 0x0]),
                            bytes([currPattern[0], 0x0, 0x0, 0x0, 0x0]),
                            ] 
                        if pattern in self.hashTable]

            for pattern in toCheck:
                for sig in self.hashTable[pattern]:
                    found = 0
                    for p in sig['raw']:
                        if (p != self.data[begin + found] and p != 0):
                            break
                        else:
                            found += 1

                        if (found == len(sig['raw'])):
                            virtAddr = begin + self.codebase + self.imagebase
                            if (len(sig['relocs']) > 0):
                                ret_relocs = self.__xtractRelocs(sig, self.data[begin:begin+found], virtAddr)
                                if len(ret_relocs) != len(sig['relocs']):
                                    #there was a direct jump / constant call in reloc, we may have a bad sigature
                                    continue

                                [found_dict['relocs'].append(reloc) for reloc in ret_relocs if reloc['call_target'] not in 
                                    [reloc['call_target'] for reloc in found_dict['relocs']]]  

                            if virtAddr not in [func['virtAddr'] for func in found_dict['functions']]:
                                found_dict['functions'].append({'virtAddr': virtAddr, 'name': sig['name'].decode("utf-8"), 'compid': sig['compid']})

                            begin += found - 1                          
            begin += 1

        resQueue.put(found_dict)

    #Threaded fuction execution wrapper
    def __executeThreaded(self, function, args, data):
        result = []
        resultQueue = Queue()
        processes = []
        chunks = self.__split_work(data, self.nthreads)

        for p in range(self.nthreads):
            processes.append(Process(target=function, args=args + [chunks[p]] + [resultQueue] + [p]))

        for p in processes:
            p.start()

        for p in processes:
            result.append(resultQueue.get(True))

        for p in processes:
            p.join()
        
        return result

    def findSignatures(self, nthreads=4):
        self.data, self.codebase, self.imagebase, self.memranges = self.__loadPE()
        self.sigThreshold = 0
        self.hashTable = self.__loadHashTable()

        ## If pe file largen than 512kb switch to MultiThreaded mode
        if len(self.data) > 1024 * 512:
            self.nthreads = nthreads

        else: #NON Threaded Execution
            self.nthreads = 1

        found_functions = []
        found_relocs = []

        #start our processes
        found = self.__executeThreaded(self.search_worker, [], self.data)

        #cleanup / merge / uniq our results
        for elem in found:
            for func in elem['functions']:
                if func['virtAddr'] not in [f['virtAddr'] for f in found_functions]:
                    found_functions.append(func)
            for reloc in elem['relocs']:
                if reloc['call_target'] not in [f['call_target'] for f in found_relocs]:
                    found_relocs.append(reloc)

        #Validate functions by checking if a relocation exists pointing to them
        confirmed = [func for func in found_functions for reloc in found_relocs if reloc['call_target'] == func['virtAddr']]

        return ({"functions": found_functions, "relocations": found_relocs, "confirmed": confirmed, "error": 0})
        
    
    def __init__(self, path):
        self.data = {}
        self.SIZE_DOS_HEADER = 0x40
        self.POS_E_LFANEW = 0x3c

        self.fname = path

