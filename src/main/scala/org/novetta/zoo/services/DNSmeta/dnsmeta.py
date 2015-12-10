# imports for PEInfo
from __future__ import division

# imports for tornado
import tornado
from tornado import web, httpserver

# imports for logging
import traceback
import os
from os import path

# imports for PEInfo
import requests
from time import localtime, strftime

def DNSMetaRun(obj):
    data = {}

    data["A"] = _get_A(domain)
    data["AAAA"] = _get_AAAA(domain)

    return data


class DNSMetaProcess(tornado.web.RequestHandler):
    def get(self, filename):
        try:
            data = DNSMetaRun()
            self.write(data)
        except Exception as e:
            self.write({"error": traceback.format_exc(e)})


class Info(tornado.web.RequestHandler):
    # Emits a string which describes the purpose of the analytics
    def get(self):
        description = """
Copyright 2015 Holmes Processing

Gathers DNS and ASN information.
        """
        self.write(description)


class PEApp(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/', Info),
            (r'/dnsmeta/([a-zA-Z0-9\-]*)', DNSMetaProcess),
        ]
        settings = dict(
            template_path=path.join(path.dirname(__file__), 'templates'),
            static_path=path.join(path.dirname(__file__), 'static'),
            # xsrf_cookies=True,
            # cookie_secret='dsfretghj867544wgryjuyki9p9lou67543/Vo=',
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        self.engine = None


def main():
    server = tornado.httpserver.HTTPServer(PEApp())
    server.listen(7720)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
