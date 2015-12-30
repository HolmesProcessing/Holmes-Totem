# imports for tornado
import tornado
import tornado.web
import tornado.httpserver
import tornado.ioloop

# imports for logging
import traceback
import os
from os import path

# get ZipParser
import ZipParser
ZipParser = ZipParser.ZipParser

class ZipError (Exception):
    def __init__ (self, status, error):
        self.status = status
        self.error  = error
    def __str__ (self):
        return str(self.status) + " - " + str(self.error)
    def __repr__ (self):
        return repr(str(self))

class ZipMetaProcess(tornado.web.RequestHandler):
    def get(self, filename):
        try:
            # read file
            fullPath = os.path.join('/tmp/', filename)
            with open(fullPath) as file:
                data = file.read()
            
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
            
            # fetch result
            result = {}
            for centralDirectory in parsedZip:
                zipfilename = centralDirectory["ZipFileName"]
                result[zipfilename] = {}
                
                for name, value in centralDirectory.iteritems():
                    if name == 'ZipExtraField':
                        continue
                    
                    if type(value) is list or type(value) is tuple:
                        result[zipfilename][name] = []
                        for element in value:
                            result[zipfilename][name].append(str(element))
                    
                    # Add way to handle dictionary.
                    #if type(value) is dict: ...
                    else:
                        result[zipfilename][name] = str(value)
                    
                if centralDirectory["ZipExtraField"]:
                    for dictionary in centralDirectory["ZipExtraField"]:
                        result[dictionary["Name"]] = {}
                        if dictionary["Name"] == "UnknownHeader":
                            for name, value in dictionary.iteritems():
                                if name == "Data":
                                    result[dictionary["Name"]][name] = name
                                else:
                                    result[dictionary["Name"]][name] = str(value)
                        else:
                            for name, value in dictionary.iteritems():
                                result[dictionary["Name"]][name] = str(value)
                else:
                    result[zipfilename]["ExtraField"] = "None"
            
            self.write(result)
        
        except ZipError as ze:
            self.set_status(ze.status, str(ze.error))
            self.write("")
        except Exception as e:
            self.set_status(500, "Unknown error happened")
            self.write({"error": traceback.format_exc(e)})


class Info(tornado.web.RequestHandler):
    # Emits a string which describes the purpose of the analytics
    def get(self):
        description = """
<p>Copyright 2015 Holmes Processing
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
    server = tornado.httpserver.HTTPServer(ZipMetaApp())
    server.listen(7715)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
