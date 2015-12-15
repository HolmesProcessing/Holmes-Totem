# imports for PEInfo
from __future__ import division

# imports for tornado
import tornado
from tornado import web, httpserver
from tornado.options import options, parse_config_file

# imports for logging
import traceback
import os
from os import path

# imports for DNSMeta
import gatherdns
from time import localtime, strftime


def DNSMetaRun(domain):
    data = {}

    dnsinfo = gatherdns.GatherDNS(options.dns_server)
    data['auth'] = dnsinfo.find_authoritative_nameserve(domain)

    # query for specified types and add to dictionary
    dnsinfo.query_domain(domain, options.rdtypes)
    for rdtype in options.rdtypes:
        function = getattr(dnsinfo, 'get_{}_record'.format(rdtype))
        result = function()
        if result is not None:
            data[rdtype] = result

    return data


class DNSMetaProcess(tornado.web.RequestHandler):
    def get(self, domain):
        try:
            data = DNSMetaRun(domain)
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


class DNSApp(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/', Info),
            (r'/dnsmeta/([a-zA-Z0-9\-]*)', DNSMetaProcess),
        ]
        settings = dict(
            template_path=path.join(path.dirname(__file__), 'templates'),
            static_path=path.join(path.dirname(__file__), 'static'),
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        self.engine = None


def main():
    # get config options
    #tornado.options.define('dns_server', default='8.8.8.8', type=str)
    tornado.options.parse_config_file("/service/service.conf")

    # start the server
    server = tornado.httpserver.HTTPServer(DNSApp())
    server.listen(7720)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
