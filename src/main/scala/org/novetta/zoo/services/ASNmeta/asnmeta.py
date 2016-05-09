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

# imports for ASNMeta
import gatherasn
from time import localtime, strftime


def ASNMetaRun(ipaddress):
    asninfo = gatherasn.GatherASN(ipaddress,
                                    options.dns_server, 
                                    options.asn_ipv4_query, 
                                    options.asn_ipv6_query,
                                    options.asn_peer_query,
                                    options.asn_name_query)
    
    asninfo.query_asn_origin()

    if asninfo.get_ip_version() == 4:
        asninfo.query_asn_peer()

    if asninfo.get_asn_number():
        asninfo.query_asn_name('AS{}'.format(asninfo.get_asn_number()))

    return asninfo.get_all_known_data()


class ASNMetaProcess(tornado.web.RequestHandler):
    def get(self, ipaddress):
        try:
            data = ASNMetaRun(ipaddress)
            self.write(data)
        except gatherasn.IPTypeError:
            raise tornado.web.HTTPError(400)
        except gatherasn.IPFormatError:
            raise tornado.web.HTTPError(404)
        except Exception as e:
            self.write({"error": traceback.format_exc(e)})


class Info(tornado.web.RequestHandler):
    # Emits a string which describes the purpose of the analytics
    def get(self):
        description = """
<p>Copyright 2015 Holmes Processing

<p>Description: Gathers ASN information for an IP address

<p>Configuration:
{}
        """.format(options.as_dict())
        self.write(description)


class ASNApp(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/', Info),
            (r'/asnmeta/(.*)', ASNMetaProcess),
            #(r'/asnmeta/((?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$)', ASNMetaProcess)
        ]
        settings = dict(
            template_path=path.join(path.dirname(__file__), 'templates'),
            static_path=path.join(path.dirname(__file__), 'static'),
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        self.engine = None


def main():
    # get config options
    tornado.options.define('dns_server', default='8.8.8.8', type=str)
    tornado.options.define('asn_ipv4_query', default='origin.asn.cymru.com', type=str)
    tornado.options.define('asn_ipv6_query', default='origin6.asn.cymru.com', type=str)
    tornado.options.define('asn_peer_query', default='peer.asn.cymru.com', type=str)
    tornado.options.define('asn_name_query', default='name.asn.cymru.com', type=str)
        
    tornado.options.parse_config_file("/service/service.conf")

    # start the server
    server = tornado.httpserver.HTTPServer(ASNApp())
    server.listen(7730)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
