# imports for tornado
import tornado
from tornado import web, httpserver

# imports for logging
import traceback
import os
from os import path

# imports for yara
import binascii
import yara

def PEInfoRun(obj):
	data = {}

	return data


class YaraProcess(tornado.web.RequestHandler):
    def get(self, filename):
        try:
            fullPath = os.path.join('/tmp/', filename)
            data = YaraRun(fullPath)
            print len(data)
            self.write(data)
        except Exception as e:
            self.write({"error": traceback.format_exc(e)})


class Info(tornado.web.RequestHandler):
    # Emits a string which describes the purpose of the analytics
    def get(self):
        description = """
Copyright 2015 Holmes Processing
Made by George Webster.
        """
        self.write(description)


class YaraApp(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/', Info),
            (r'/yara/([a-zA-Z0-9\-]*)', YaraProcess),
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
    server = tornado.httpserver.HTTPServer(YaraApp())
    server.listen(7701, address="127.0.0.1")
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()