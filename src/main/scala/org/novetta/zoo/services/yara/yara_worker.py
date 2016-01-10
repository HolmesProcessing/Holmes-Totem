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
#import akka
from io import StringIO
import base64
import binascii
import configparser
import sys
import yara

# Set up Tornado options
define("port", default=8080, help="port to run", type=int)

class YaraHandler(tornado.web.RequestHandler):
	@property
	def YaraEngine(self):
		return yara.load(sys.argv[1])

class YaraProcess(YaraHandler):
	def process(self, filename, rules=None):
		try:
			if rules:
				ruleBuff = StringIO()
				ruleBuff.write(rules)
				ruleBuff.seek(0)

				rules = yara.load(file=ruleBuff)
				results = rules.match(filename[0], external={'filename': filename[1]})
			else:
				results = self.YaraEngine.match(filename[0], external=external={'filename': filename[1]})
			results2 = list(map(lambda x: {"rules": x.rules}, results))
			return results2
		except Exception as e:
			return e

	def get(self, filename):
		print("get req")
		try:
			fullPath = (os.path.join('/tmp/', filename), filename)
			data = self.process(fullPath)
			print(data)
			self.write({"yara": data})
		except Exception as e:
			print(e)
			self.write({"error": traceback.format_exc(e)})

	def post(self, filename):
		print("post req")
		print(self.request.body)
		try:
			fullPath = os.path.join('/tmp/', filename)
			rules = base64.b64decode(self.get_body_argument('custom_rule')).decode('latin-1')
			data = self.process(fullPath, rules)
			print(data)
			self.write({"yara": data})
		except Exception as e:
			print(e)
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
	tornado.options.parse_command_line()
	server = tornado.httpserver.HTTPServer(YaraApp())
	server.listen(options.port)
	print("starting the yara worker on port {}".format(options.port))
	tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
	main()
