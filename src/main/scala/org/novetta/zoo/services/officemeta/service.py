# imports for tornado
import tornado.web, tornado.httpserver, tornado.ioloop, tornado.options

# imports for officemeta
from parser.service_helper  import ServiceHelper
from parser.error           import OfficeMetaError
from library.services       import ServiceConfig
import traceback
import os


# get config and init Tornado
Config = ServiceConfig("./service.conf")
tornado.options.define("port", default=int(Config.settings.port,10),
    help="port to run", type=int)


class OfficeMetaProcess(tornado.web.RequestHandler):
    def get(self, filename):
        try:
            oparser = ServiceHelper(os.path.join('/tmp/', filename))
            self.write(oparser.parse_office_doc())
        except OfficeMetaError as ome:
            self.set_status(ome.status, str(ome.error))
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


class ServiceApp(tornado.web.Application):
    def __init__(self):
        handlers = [
            (Config.settings.infourl + r'', Info),
            (Config.settings.analysisurl + r'/([a-zA-Z0-9\-\.]*)', OfficeMetaProcess),
        ]
        settings = dict(
            template_path=os.path.join(os.path.dirname(__file__), 'templates'),
            static_path=os.path.join(os.path.dirname(__file__), 'static'),
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        self.engine = None


def main():
    tornado.options.parse_command_line()
    server = tornado.httpserver.HTTPServer(ServiceApp())
    server.listen(tornado.options.options.port)
    print("starting the office_meta worker on port {}".format(
        tornado.options.options.port))
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
