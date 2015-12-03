# imports for tornado
import tornado
from tornado import web, httpserver, iploop

# imports for logging
import traceback
import os
from os import path

# imports for yara to work
import akka
import binascii
import ConfigParser
import sys
import yara


class YaraHandler(tornado.web.RequestHandler):
	@property
	def YaraEngine(self):
		if not self.application.engine:
			try:
				self.application.engine = yara.load(sys.argv[1])
			except Exception as e:
				print e
		return self.application.engine


class YaraProcess(YaraHandler):
	def process(self, tup, rule=None):
		try:
			if rules:
				rules = yara.load(rules)
				results = rules.match(tup)
			else:
				results = self.YaraEngine.match(tup)
			results2 = map(lambda x: {"rule": x.rule}, results)
			return results2
		except Exception, e:
			return e

	def get(self, filename):
		try:
			fullPath = os.path.join('/tmp/', filename)
			data = self.process(fullPath)
			self.write({"yara": data})
		except Exception as e:
			self.write({"error": traceback.format_exc(e)})

	def post(self, filename):
		try:
			fullPath = os.path.join('/tmp/', filename)
			custom_rule = self.get_body_argument('custom_rule')
			data = self.process(fullPath, custom_rule)
			self.write({"yara": data})
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
			static_path=path.join(path.dirname(__file__), 'static')
		)
		tornado.web.Application.__init__(self, handlers, **settings)
		self.engine = None


def main():
	server = tornado.httpserver.HTTPServer(YaraApp())
	server.listen(7701, address="127.0.0.1")
	tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
	main()