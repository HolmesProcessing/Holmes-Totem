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

# Set up Tornado options
define("port", default=8080, help="port to run", type=int)

class YaraHandler(tornado.web.RequestHandler):
    @property
    def YaraEngine(self):
        return yara.load(sys.argv[1])

class PEiDProcess(YaraHandler):
    def process(self, filename, rules=None):
        try:
            if rules:
                ruleBuff = StringIO()
                ruleBuff.write(rules)
                ruleBuff.seek(0)

                rules = yara.load(file=ruleBuff)
                results = rules.match(filename[0], externals={'filename': filename[1]})
            else:
                results = self.YaraEngine.match(filename[0], externals={'filename': filename[1]})
            results2 = list(map(lambda x: {"rule": x.rule}, results))
            return results2
        except Exception as e:
            return e

    def get(self, filename):
        print("Received get request")
        try:
            fullPath = (os.path.join('/tmp/', filename), filename)
            data = self.process(fullPath)
            self.write({"peid": data})
        except Exception as e:
            self.write({"error": traceback.format_exc(e)})

    def post(self, filename):
        print("Received post request")
        print(self.request.body)
        try:
            fullPath = os.path.join('/tmp/', filename)
            rules = base64.b64decode(self.get_body_argument('custom_rule')).decode('latin-1')
            data = self.process(fullPath, rules)
            self.write({"peid": data})
        except Exception as e:
            self.write({"error": traceback.format_exc(e)})


class Info(tornado.web.RequestHandler):
    # Emits a string which describes the purpose of the analytics
    def get(self):
        description = """
<p>Copyright 2015 Holmes Processing

<p>Description: Provides PEiD signature matching for samples using a collective 
set of signatures or a provided custom signature.

        """
        self.write(description)


class PEiDApp(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/', Info),
            (r'/peid/([a-zA-Z0-9\-]*)', PEiDProcess),
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
    print("starting the peid worker on port {}".format(options.port))
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
