#Search Function Signatures from DB (see richDB.py) in pe32 files,
#using rich header information and relocation data

#std imports
import sys, os, struct, time, pickle
from collections import defaultdict
from multiprocessing import Process, Queue

#imported libs
import pefile

class MachineVersionError(Exception):
    pass

class NoMatchingSignatures(Exception):
    pass

class UnknownRelocationError(Exception):
    pass

def err2str(code):
    return{
        -1: "Non x86 PE File",
        -2: "No usable Signatures found (check ./signatures/richDB.py for generating them)",
        -3: "Unknown / non implemented relocation type found"
        }[code]

class RichFuncFinder:

    def __init__(self, fname, rich_data, nthreads=4):
        self.fname = fname
        self.rich_data = rich_data
        self.nthreads = nthreads
        self.bucketSize = 5
        self.sigThreshold = 0
        self.data, self.codebase, self.imagebase, self.memranges = self.loadPE()
        self.hashTable = self.loadHashTable()

    #PE stuff
    def loadPE(self):
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

    #load signatures from storage
    def loadHashTable(self):

        hashTable = defaultdict(list) #signature store
        threshold = 7 #skip signatures < 7 bytes
        loaded = 0 # how many signatures were loaded
        discarded = 0 # how many signatures were below threshold

        #rich header data
        rich_data = self.rich_data

        #load db according to found rich header values
        for cmpid in rich_data['cmpids']:
            if(os.path.isfile("./signatures/" + str(cmpid['compid'])+ ".pickle")):
                with open("./signatures/" + str(cmpid['compid'])+ ".pickle", 'rb') as infile:
                    curr_sig_file = pickle.load(infile)

                    #load signatures into hashtable
                    for sig in curr_sig_file:                   
                        if len(sig['raw']) >= threshold:
                            hashTable[sig['raw'][:self.bucketSize]].append(sig)
                            loaded += 1
                            self.sigThreshold = max(self.sigThreshold, len(sig['raw'])) #used for multithread overlapping
                        else:
                            discarded += 1

        if loaded == 0:
            raise NoMatchingSignatures()

        return hashTable

    #main search function
    def parse(self):

        #if pe file largen than 512kb switch to MultiThreaded mode
        if len(self.data) > 1024 * 512: 
            start = time.perf_counter()

            found_functions = []
            found_relocs = []

            #start our processes
            found = self.executeThreaded(self.search_worker, [], self.data)

            stop = time.perf_counter()

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

        ## NON Threaded Loop for small files (<512kb) below
        found_functions = [] #hold all currently found function signatures
        found_relocs = []
        pos = 0
        start = time.perf_counter()

        #Main loop, load 5 bytes from binary, check if exist in our hashtable, continue if found with detailed signature matching
        while (pos < (len(self.data) - self.bucketSize)):

            #workaround for signatures starting with only 1, 2, 3 or 4 bytes before relocation e.g. 0x42424242400 + 0x4242420000 ...
            currPattern = self.data[pos:pos+self.bucketSize]
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
                        if (p != self.data[pos + found] and p != 0):
                            break
                        else:
                            found += 1

                        if (found == len(sig['raw'])):
                            virtAddr = pos + self.codebase + self.imagebase
                            if (len(sig['relocs']) > 0):
                                ret_relocs = self.xtractRelocs(sig, self.data[pos:pos+found], virtAddr)
                                if len(ret_relocs) != len(sig['relocs']):
                                    #there was a direct jump / constant call in reloc, we may have a bad sigature
                                    continue

                                [found_relocs.append(reloc) for reloc in ret_relocs if reloc['call_target'] not in 
                                    [reloc['call_target'] for reloc in found_relocs]]  

                            if virtAddr not in [func['virtAddr'] for func in found_functions]:
                                found_functions.append({'virtAddr': virtAddr, 'name': sig['name'].decode("utf-8"), 'compid': sig['compid']})

                            pos += found - 1                            
            pos += 1
            
        stop = time.perf_counter()
        
        confirmed = [func for func in found_functions for reloc in found_relocs if reloc['call_target'] == func['virtAddr']]

        return ({"functions": found_functions, "relocations": found_relocs, "confirmed": confirmed, "error": 0})

    # Worker Process, checking a chunk of the binary with some overlap to other workers
    def search_worker(self, chunk, resQueue, threadid):
        found_dict = {"functions": [], "relocs": []}
        #overlap_factor = 16 # start - len(chunk) / overlap_factor | stop + len(chunk) / overlap_factor
        #begin = int(max(threadid * len(chunk) - (len(chunk) / overlap_factor), 0)) #start half a chunk size into other search space to overlap
        #end = int(min((threadid+1) * len(chunk)  + (len(chunk) / overlap_factor), len(self.data)))

        begin = int(max(threadid * len(chunk) - self.sigThreshold*2, 0)) #overlap double the largest signature
        end = int(min((threadid+1) * len(chunk)  + self.sigThreshold*2, len(self.data)))

        while (begin < end - self.bucketSize):
            #workaround for signatures starting with only 1 to 4 bytes before relocation e.g. 0x424242 + 0x424200 + 0x420000
            currPattern = self.data[begin:begin+self.bucketSize]
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
                                ret_relocs = self.xtractRelocs(sig, self.data[begin:begin+found], virtAddr)
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
    def executeThreaded(self, function, args, data):
        result = []
        resultQueue = Queue()
        processes = []
        chunks = self.split_work(data, self.nthreads)

        for p in range(self.nthreads):
            processes.append(Process(target=function, args=args + [chunks[p]] + [resultQueue] + [p]))

        for p in processes:
            p.start()

        for p in processes:
            result.append(resultQueue.get(True))

        for p in processes:
            p.join()
        
        return result

    #taken from rich.py
    def u32(self, x):
        return struct.unpack("<I", x)[0]

    def split_work(self, work, nr):
        return [work[i::nr] for i in range(nr)]

    #If we find a matching signature in our binary, this can be used to extract all relocations stored for this signature in our db
    def xtractRelocs(self, sig, dat, virtAddr):

        relocs = sig['relocs']
        syms = sig['syms']
        found_relocs = []

        #Parse all relocations in Signature
        for reloc in relocs:
            reloc_addr = self.u32(dat[reloc['addr']:reloc['addr']+4]) #extract relocation address ("Call Target")
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
