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
import gatherasn
from time import localtime, strftime


def ASNMetaRun(ipaddress):
    data = {}

    asninfo = gatherasn.GatherASN(options.dns_server, 
                                    options.asn_ipv4_query, 
                                    optiions.asn_ipv6_query,
                                    asn_peer_query,
                                    asn_name_query)
    
    asninfo.query_asn_origin(ipaddress)
    asninfo.query_asn_peer(ipaddress)

    asn_number = asninfo.get('get_asn_number', False)
    if asn_number:
        ansinfo.query_asn_name('AS{}'.format(asn_number))

    return asninfo.get_all_known_data()


class ASNMetaProcess(tornado.web.RequestHandler):
    def get(self, ipaddress):
        try:
            data = ASNMetaRun(ipaddress)
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


class ASNApp(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/', Info),
            (r'/asnmeta/([a-zA-Z0-9\-]*)', ASNMetaProcess),
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
    server = tornado.httpserver.HTTPServer(ASNApp())
    server.listen(7720)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
