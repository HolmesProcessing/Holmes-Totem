# imports for tornado
import tornado
from tornado import web, httpserver

# imports for logging
import traceback
import os
from os import path

# imports for yara to work
import binascii
import yara
import akka
import sys


class YaraHandler(tornado.web.RequestHandler):
	@property
	def YaraEngine(self):
		if not self.application.engine:
			try:
				self.application.engine = yara.compile(sys.argv[1])
			except Exception as e:
				print e
		return self.application.engine


class YaraProcess(YaraHandler):
	def process(self, tup):
		try:
			results = self.YaraEngine.match(tup)
			results2 = map(lambda x: {"rule": x.rule}, results)
			return results2
		except Exception, e:
			return e

    def get(self, filename):
        try:
            fullPath = os.path.join('/tmp/', filename)
            data = self.process(fullPath)
            self.write({"yara": data)
        except Exception as e:
            self.write({"error": traceback.format_exc(e)})


class Info(tornado.web.RequestHandler):
    # Emits a string which describes the purpose of the analytics
    def get(self):
        description = """
Provides Yara signature matching for samples using a collective 
set of signatures or a provided custom signature.
Copyright 2015 Holmes Processing
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