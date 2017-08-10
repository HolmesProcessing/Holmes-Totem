# imports for tornado
import tornado
from tornado import web, httpserver, ioloop

# imports for logging
import traceback
import os
from os import path

# imports for rich
import richlibrary

#imports for reading configuration file
import json

# Reading configuration file
def ServiceConfig(filename):
    configPath = filename
    try:
        config = json.loads(open(configPath).read())
        return config
    except FileNotFoundError:
        raise tornado.web.HTTPError(500)

# Get service meta information and configuration
Config = ServiceConfig("./service.conf")

Metadata = {
    "Name"        : "Rich Header",
    "Version"     : "1.0",
    "Description" : "./README.md",
    "Copyright"   : "Copyright 2017 Holmes Group LLC",
    "License"     : "./LICENSE"
}


def RichHeaderRun(objpath):
    parser = richlibrary.RichLibrary(objpath)
    return parser.parse()


class Service(tornado.web.RequestHandler):
    def get(self):
        try:
            filename = self.get_argument("obj", strip=False)
            fullPath = os.path.join('/tmp/', filename)
            data = RichHeaderRun(fullPath)
            self.write(data)
        except tornado.web.MissingArgumentError:
            raise tornado.web.HTTPError(400)
        except richlibrary.MZSignatureError:
            self.write({'error': richlibrary.err2str(-2)})
        except richlibrary.PESignatureError:
            self.write({'error': richlibrary.err2str(-3)})
        except richlibrary.RichSignatureError:
            self.write({'error': richlibrary.err2str(-4)})
        except richlibrary.DanSSignatureError:
            self.write({'error': richlibrary.err2str(-5)})
        except richlibrary.PaddingError:
            self.write({'error': richlibrary.err2str(-6)})
        except richlibrary.RichLengthError:
            self.write({'error': richlibrary.err2str(-7)})
        except Exception as e:
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
            name        = str(Metadata["Name"]).replace("\n", "<br>"),
            version     = str(Metadata["Version"]).replace("\n", "<br>"),
            description = str(Metadata["Description"]).replace("\n", "<br>"),
            license     = str(Metadata["License"]).replace("\n", "<br>")
        )
        self.write(info)


class Application(tornado.web.Application):
    def __init__(self):

        for key in ["Description", "License"]:
            fpath = Metadata[key]
            if os.path.isfile(fpath):
                with open(fpath) as file:
                    Metadata[key] = file.read()

        handlers = [
            (r'/', Info),
            (r'/analyze/', Service),
        ]
        settings = dict(
            template_path=path.join(path.dirname(__file__), 'templates'),
            static_path=path.join(path.dirname(__file__), 'static'),
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        self.engine = None


def main():
    server = tornado.httpserver.HTTPServer(Application())
    server.listen(Config["settings"]["httpbinding"])
    try:
        tornado.ioloop.IOLoop.current().start()
    except KeyboardInterrupt:
        tornado.ioloop.IOLoop.current().stop()


if __name__ == '__main__':
    main()
