# imports for tornado
# imports for tornado
import tornado
from tornado import web, httpserver, ioloop
import tornado.options
from tornado.options import define, options


# imports for logging
import traceback
import os
from os import path
import mmap

# get ZipParser
import ZipParser
ZipParser = ZipParser.ZipParser

# Set up Tornado options
define("port", default=8080, help="port to run", type=int)

class ZipError (Exception):
    __slots__ = ["status", "error"]
    def __init__ (self, status, error):
        self.status = status
        self.error  = error
    def __str__ (self):
        return str(self.status) + " - " + str(self.error)
    def __repr__ (self):
        return repr(str(self))


class ResultSet (object):
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


class MemoryEfficientFile (object):
    """
    Low memory footprint file-like object. (read only access)
    Reading and finding does not advance the offset.
    If you need to adjust the offset, use seek or seek_relative.
    """
    __slots__ = ["file", "datamap", "size", "offset"]
    def __init__ (self, filename):
        self.file     = open(filename)
        self.datamap  = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        self.size     = self.datamap.size()
        self.offset   = 0
    
    def close (self):
        self.datamap.close()
        self.file.close()
        del(self.file)
        del(self.offset)
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
        return self.datamap[(self.offset+start):(self.offset+stop)]
    
    def seek (self, offset):
        self.offset = offset
    def seek_relative (self, offset):
        self.offset += offset  # add offset adjustment ability
    def tell (self):
        return self.offset
    
    def find (self, needle, offset=0):
        result = self.datamap.find(needle, self.offset+offset)
        if result != -1:
            result -= self.offset
        return result
    def startswith (self, needle):
        return self[0:len(needle)] == needle
    
    def subfile (self, start):
        class MemoryEfficientSubFile (MemoryEfficientFile):
            def __init__ (self, file, datamap, start, size):
                self.file     = file
                self.datamap  = datamap
                self.size     = size
                self.offset   = start
            def close (self):
                pass  # remove close ability
            def subfile (self, start):
                pass  # remove subfile ability
        return MemoryEfficientSubFile(
            self.file, self.datamap, self.offset+start, self.size)
    
    # provide interface for built-ins
    def __getitem__ (self, key):
        if isinstance(key, slice):
            return self.read(key.start, key.stop)
        else:
            return self.read(key.start, key.start+1)
    
    def __len__ (self):
        return self.size




class ZipMetaProcess(tornado.web.RequestHandler):
    def get(self, filename):
        resultset = ResultSet()
        try:
            # read file
            fullPath = os.path.join('/tmp/', filename)
            data     = MemoryEfficientFile(fullPath)
            
            # exclude non-zip
            if len(data) < 4:
                raise ZipError(400, "Not enough filedata.")
            if data[:4] not in [ZipParser.zipLDMagic, ZipParser.zipCDMagic]:
                raise ZipError(400, "Not a zip file.")
            
            # parse
            parser    = ZipParser(data)
            parsedZip = parser.parseZipFile()
            if not parsedZip:
                raise ZipError(400, "Could not parse file as a zip file")
            
            # clean up
            data.close()
            
            # fetch result
            for centralDirectory in parsedZip:
                zipfilename = centralDirectory["ZipFileName"]
                zipentry = ResultSet()
                
                for name, value in centralDirectory.iteritems():
                    if name == 'ZipExtraField':
                        continue
                    
                    if type(value) is list or type(value) is tuple:
                        for element in value:
                            zipentry.add(name, str(element))
                    
                    # Add way to handle dictionary.
                    #if type(value) is dict: ...
                    else:
                        zipentry.add(name, str(value))
                    
                if centralDirectory["ZipExtraField"]:
                    for dictionary in centralDirectory["ZipExtraField"]:
                        zipextra = ResultSet()
                        if dictionary["Name"] == "UnknownHeader":
                            for name, value in dictionary.iteritems():
                                if name == "Data":
                                    value = "Data"
                                zipextra.add(name, str(value))
                        else:
                            for name, value in dictionary.iteritems():
                                zipextra.add(name, str(value))
                        zipentry.add(dictionary["Name"], zipextra.data)
                else:
                    zipentry.add("ZipExtraField", "None")
                
                resultset.add(zipfilename, zipentry.data)
            
            self.write({"files": resultset.data})
        
        except ZipError as ze:
            self.set_status(ze.status, str(ze.error))
            self.write("")
        except Exception as e:
            self.set_status(500, str(e))
            self.write({"error": traceback.format_exc(e)})


class Info(tornado.web.RequestHandler):
    # Emits a string which describes the purpose of the analytics
    def get(self):
        description = """
<p>Copyright 2015 Holmes Processing

<p>Description: Gathers meta information about a zip file.

<p>Usage: ip-address:port/zipmeta/sampleID
        """
        self.write(description)


class ZipMetaApp(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/', Info),
            (r'/zipmeta/([a-zA-Z0-9\-]*)', ZipMetaProcess),
        ]
        settings = dict(
            template_path=path.join(path.dirname(__file__), 'templates'),
            static_path=path.join(path.dirname(__file__), 'static'),
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        self.engine = None


def main():
    tornado.options.parse_command_line()
    server = tornado.httpserver.HTTPServer(ZipMetaApp())
    server.listen(options.port)
    print("starting the zipmeta worker on port {}".format(options.port))
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
