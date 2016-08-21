# imports for tornado
import tornado
from tornado import web, httpserver, ioloop

# imports for logging
import traceback
import os
from os import path

# imports for DNSMeta
import gatherdns
from time import localtime, strftime

# imports for services
from holmeslibrary.services import ServiceConfig

# Get service meta information and configuration
Config = ServiceConfig("./service.conf")
Config.dnsmeta.rdtypes = [item.strip() for item in Config.dnsmeta.rdtypes.split(',')]

def DNSMetaRun(domain):
    data = {}

    dnsinfo = gatherdns.GatherDNS(domain, Config.dnsmeta.dns_server)
    data['auth'] = dnsinfo.find_authoritative_nameserver(domain)

    # query for specified types and add to dictionary
    dnsinfo.query_domain(Config.dnsmeta.rdtypes)
    for rdtype in Config.dnsmeta.rdtypes:
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
        except gatherdns.DomainError:
            raise tornado.web.HTTPError(404)
        except Exception as e:
            self.write({"error": traceback.format_exc(e)})


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
            name        = str(Config.metadata.name).replace("\n", "<br>"),
            version     = str(Config.metadata.version).replace("\n", "<br>"),
            description = str(Config.metadata.description).replace("\n", "<br>"),
            license     = str(Config.metadata.license).replace("\n", "<br>"),
        )
        self.write(info)


class DNSApp(tornado.web.Application):
    def __init__(self):
        handlers = [
            (Config.settings.infourl + r'', Info),
            (Config.settings.analysisurl + r'/(.*)', DNSMetaProcess),
        ]
        settings = dict(
            template_path=path.join(path.dirname(__file__), 'templates'),
            static_path=path.join(path.dirname(__file__), 'static'),
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        self.engine = None


def main():
    server = tornado.httpserver.HTTPServer(DNSApp())
    server.listen(Config.settings.port)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == '__main__':
    main()
