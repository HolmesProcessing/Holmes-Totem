import mmap
# import tempfile
# import shutil
# import os

class LargeFileReader (object):
    """
    FOr mapping file to virtual memory. 
    File-like (read-only) object trimmed for low memory footprint.
    Reading and finding does not advance the offset.
    Usage:
        # open
        file = LargeFileReader("/filepath")
        # find
        start = file.find("needle")
        # access data, still offset 0
        file[32987000:2323493493]
        # create a subfile at offset start
        subfile = file.subfile(start)
        # find a needle somewhere after the offset, relative to the offset
        position = subfile.find("second needle")
        # adjust offset in the subfile to after the previous find
        subfile.seek_relative(position+1)
    """
    __slots__ = ["file","datamap","size","offset"]
    def __init__ (self, filename):
        self.file     = open(filename, "rb")
        self.datamap  = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        self.offset   = 0
        self.size     = self.datamap.size()
    
    def close (self):
        self.datamap.close()
        del(self.datamap)
        self.file.close()
        del(self.file)
        del(self.offset)
        del(self.size)
        del(self)
    
    # provide base functionality
    def read (self, start, stop):
    # def read(self):
        if start is None or start < 0:
            start = 0
        if stop is None or stop > self.size:
            stop = self.size
        if start >= self.size:
            start = self.size - 1
        if stop > self.size:
            stop = self.size
        self.datamap.seek(0)
        return self.datamap[(self.offset+start):(self.offset+stop)]
    
    def seek (self, position):
        self.offset = min(self.size, max(0, position))
        self.datamap.seek(self.offset)
    def seek_relative (self, offset):
        self.seek(self.offset + offset)
    
    def tell (self):
        return self.offset
    def tell_map (self):
        return self.datamap.tell()
    
    def find (self, needle):
        self.datamap.seek(0)
        result = self.datamap.find(needle, self.offset)
        if result != -1:
            result -= self.offset
        return result
    
    def startswith (self, needle):
        return self[0:len(needle)].decode('UTF-8') == needle
    
    # extended slicing
    def __getitem__ (self, key):
        if isinstance(key, slice):
            return self.read(key.start, key.stop)
        else:
            return self.read(key.start, key.start+1)
    
    def subfile (self, start):
        class LargeFileSubReader (LargeFileReader):
            __slots__ = ["file","datamap","size","offset"]
            # lightweight subtype of LargeFileReader offering adjusted offset
            def __init__ (self, file, datamap, start, size):
                self.file     = file
                self.datamap  = datamap
                self.size     = size
                self.offset   = start
            def close (self):
                pass  # remove close ability
            def subfile (self, start):
                pass  # remove subfile ability
        return LargeFileSubReader(self.file, self.datamap, self.offset+start, self.size)
    
    # provide standard functions
    def __len__ (self):
        return self.size

