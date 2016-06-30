import tornado
from tornado import web, httpserver, ioloop
import tornado.options
from tornado.options import define, options

import traceback
import os
from os import path

import ZipParser
ZipParser = ZipParser.ZipParser
from library.services import ServiceRequestError, ServiceResultSet, ServiceConfig
from library.files    import LargeFileReader

# Get service meta information and configuration
Config = ServiceConfig("./service.conf")
# Set up Tornado options
define("port", default=int(Config.settings.port,10), help="port to run", type=int)

class ZipError (ServiceRequestError):
    pass

class ZipMetaProcess(tornado.web.RequestHandler):
    def get(self, filename):
        resultset = ServiceResultSet()
        try:
            # read file
            fullPath = os.path.join('/tmp/', filename)
            data     = LargeFileReader(fullPath)
            
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
                zipentry = ServiceResultSet()
                
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
                        zipextra = ServiceResultSet()
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
            
            self.write({"filecount": resultset.size, "files": resultset.data})
        
        except ZipError as ze:
            self.set_status(ze.status, str(ze.error))
            self.write("")
        except Exception as e:
            self.set_status(500, str(e))
            self.write({"error": traceback.format_exc(e)})


class Info(tornado.web.RequestHandler):
    # Emits a string which describes the purpose of the analytics
    def get(self):
        info = """
            <p>{name:s} - {version:s}</p>
            <hr>
            <p>{description:s}</p>
            <hr>
            <p>{license:s}
        """.format(
            name        = str(Config.metadata.name).replace("\n", "<br>"),
            version     = str(Config.metadata.version).replace("\n", "<br>"),
            description = str(Config.metadata.description).replace("\n", "<br>"),
            license     = str(Config.metadata.license).replace("\n", "<br>")
        )
        self.write(info)


class ZipMetaApp(tornado.web.Application):
    def __init__(self):
        handlers = [
            (Config.settings.infourl + r'', Info),
            (Config.settings.analysisurl + r'/([a-zA-Z0-9\-\.]*)', ZipMetaProcess),
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
