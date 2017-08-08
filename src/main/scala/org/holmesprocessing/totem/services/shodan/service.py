import tornado
import tornado.web
import tornado.httpserver
import tornado.ioloop

import sys
import os
from os import path
import shodan

from shodanfile import runShodan
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

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
api = shodan.Shodan(Config["shodan"]["apikey"])

Metadata = {
    "Name"        : "Shodan",
    "Version"     : "1.0",
    "Description" : "./README.md",
    "Copyright"   : "Copyright 2016 Holmes Group LLC",
    "License"     : "./LICENSE"
}


class Service(tornado.web.RequestHandler):
    def get(self):
        input = self.get_argument("obj", strip=False)
        data = runShodan(api, input)
        self.write(data)


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
