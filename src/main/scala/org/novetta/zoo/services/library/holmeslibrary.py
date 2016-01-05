import os
import tempfile
import shutil
import mmap


class Meta():
    needed_meta_data = ["ServiceName", "ServiceVersion", "ServiceConfig", "ObjectCategory", "ObjectType"]

    """
    Class for storing metadata for a service.
    Metadata are read from a file with lines of the form:
       key = value
    """
    def __init__(self, cfg="META"):
        self.data = dict()
        f = open(cfg)
        for line in f:
            if(line.strip() == ""):
                continue
            l = line.split("=")
            if len(l) == 2:
                key = l[0].strip()
                value = l[1].strip()
                self.data[key] = value
            else:
                print("%s malformed. Ignoring line: %s" % (cfg, line))
                #exit(-1)
        for needed in Meta.needed_meta_data:
            if self.data.get(needed) is None:
                print("%s is not configured in %s!" % (needed, cfg))

    def getServiceName(self):
        return self.data["ServiceName"]
    def getServiceVersion(self):
        return self.data["ServiceVersion"]
    def getServiceConfig(self):
        return self.data["ServiceConfig"]
    def getObjectCategory(self):
        return self.data["ObjectCategory"]
    def getObjectType(self):
        return self.data["ObjectType"]



class TempAnalysisFile(object):
    """
    Temporary Analysis File class.
    """

    def __init__(self, obj):
        self.obj = obj
        #print(obj)

    def __enter__(self):
        """
        Create the temporary file on disk.
        """

        tempdir = tempfile.mkdtemp()
        self.directory = tempdir
        tfile = os.path.join(tempdir, self.obj)
        with open(tfile, "wb") as f:
            f.write(open(self.obj).read().encode())
        return tfile

    def __exit__(self, type, value, traceback):
        """
        Cleanup temporary file on disk.
        """

        if os.path.isdir(self.directory):
            shutil.rmtree(self.directory)



class ServiceRequestError (Exception):
    """
    Basic exception class.
    Usage (context: tornado.web.RequestHandler):
       self.set_status(e.status)
       self.write(e)
    """
    __slots__ = ["status", "error"]
    def __init__ (self, status, error):
        self.status = status
        self.error  = error
    def __str__ (self):
        return str(self.status) + ": " + str(self.error)
    def __repr__ (self):
        return repr(str(self))
    def __iter__ (self):
        yield "status"
        yield "error"
    def __getitem__ (self, key):
        return getattr(self,key)



class ResultSet (object):
    """
    Light weight result set class.
    Usage (context: tornado.web.RequestHandler):
        resultset = ResultSet()
        subset = Resultset
        subset.add("key1","value")
        subset.add("key2","value")
        resultset.add("key3",subset)
        self.write(resultset)
    Output:
        {"key3":{"key1":"value","key2":"value"}}
    """
    __slots__ = ["data"]
    def __init__(self):
        self.data = {}
    def add(self, key, value):
        if key in self.data:
            if isinstance(self.data[key], list):
                self.data[key].append(value)
            else:
                cpy = self.data[key]
                self.data[key] = []
                self.data[key].append(cpy)
                self.data[key].append(value)
        else:
            self.data[key] = value


class BigFile (object):
    """
    File-like (read-only) object trimmed for low memory footprint.
    Usage:
        # open
        file = BigFile("/filepath")
        # find
        start = file.find("needle")
        # access data
        file[32987000:2323493493]
        # create a subfile at offset start
        subfile = file.subfile(start)
        # find a needle somewhere after the offset, relative to the offset
        position = subfile.find("second needle")
        # adjust offset in the subfile
        subfile.adjust(position+1)
    """
    __slots__ = ["file","datamap","size","offset"]
    def __init__ (self, filename):
        self.file     = open(filename)
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
        self.datamap.seek(self.offset+position)
    
    def tell (self):
        return self.datamap.tell()
    
    def find (self, needle):
        self.datamap.seek(0)
        result = self.datamap.find(needle, self.offset)
        if result != -1:
            result -= self.offset
        return result
    
    def startswith (self, needle):
        return self[0:len(needle)] == needle
    
    # extended slicing
    def __getitem__ (self, key):
        if isinstance(key, slice):
            return self.read(key.start, key.stop)
        else:
            return self.read(key.start, key.start+1)
    
    def subfile (self, start):
        class SubFile (BigFile):
            __slots__ = ["file","datamap","size","offset"]
            # lightweight subtype of BigFile offering adjusted offset
            def __init__ (self, file, datamap, start, size):
                self.file     = file
                self.datamap  = datamap
                self.size     = size
                self.offset   = start
            def close (self):
                pass  # remove close ability
            def subfile (self, start):
                pass  # remove subfile ability
            def adjust (self, start):
                self.offset += start  # add offset adjustment ability
        return SubFile(self.file, self.datamap, self.offset+start, self.size)
    
    # provide standard functions
    def __len__ (self):
        return self.size