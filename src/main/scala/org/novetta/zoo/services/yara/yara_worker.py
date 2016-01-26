# imports for tornado
import tornado
from tornado import web, httpserver, ioloop
import tornado.options
from tornado.options import define, options

# imports for logging
import traceback
import os
from os import path

# imports for yara to work
from io import StringIO
import base64
import binascii
import sys
import yara

# imports for services
from holmeslibrary.services import ServiceConfig

# Get service meta information and configuration
Config = ServiceConfig("./service.conf")
# Set up Tornado options
define("port", default=Config.settings.port, help="port to run", type=int)

class YaraHandler(tornado.web.RequestHandler):
    @property
    def YaraEngine(self):
        if not "load" in dir(yara):
            return yara.load_rules(Config.settings.yararules)
        return yara.load(Config.settings.yararules)

class YaraProcess(YaraHandler):
    def process(self, filename, rules=None):
        if rules:
            ruleBuff = StringIO()
            ruleBuff.write(rules)
            ruleBuff.seek(0)
            if not "load" in dir(yara):
                results = yara.load_rules(file=ruleBuff)
            else:
                rules = yara.load(file=ruleBuff)
            results = rules.match(filename[0], externals={'filename': filename[1]})
        else:
            results = self.YaraEngine.match(filename[0], externals={'filename': filename[1]})
        results2 = list(map(lambda x: {"rule": x.rule}, results))
        return results2

    def get(self, filename):
        print("Received get request")
        try:
            fullPath = (os.path.join('/tmp/', filename), filename)
            data = self.process(fullPath)
            self.write({"yara": data})
        except Exception as e:
            self.write({"error": traceback.format_exc(e)})

    def post(self, filename):
        print("Received post request")
        print(self.request.body)
        try:
            fullPath = os.path.join('/tmp/', filename)
            rules = base64.b64decode(self.get_body_argument('custom_rule')).decode('latin-1')
            data = self.process(fullPath, rules)
            self.write({"yara": data})
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
            name        = str(Config.metadata.name).replace("\n", "<br>"),
            version     = str(Config.metadata.version).replace("\n", "<br>"),
            description = str(Config.metadata.description).replace("\n", "<br>"),
            license     = str(Config.metadata.license).replace("\n", "<br>")
        )
        self.write(info)


class YaraApp(tornado.web.Application):
    def __init__(self):
        handlers = [
            (Config.settings.infourl + r'', Info),
            (Config.settings.analysisurl + r'/([a-zA-Z0-9\-\.]*)', YaraProcess),
        ]
        settings = dict(
            template_path=path.join(path.dirname(__file__), 'templates'),
            static_path=path.join(path.dirname(__file__), 'static')
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        self.engine = None


def main():
    tornado.options.parse_command_line()
    server = tornado.httpserver.HTTPServer(YaraApp())
    server.listen(options.port)
    print("starting the yara worker on port {}".format(options.port))
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
