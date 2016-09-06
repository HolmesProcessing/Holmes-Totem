# imports for tornado
import tornado
from tornado import web, httpserver, ioloop

# imports for logging
import traceback
import os
from os import path

# imports for ASNMeta
import gatherasn
from time import localtime, strftime

# imports for services
from holmeslibrary.services import ServiceConfig

# Get service meta information and configuration
Config = ServiceConfig("./service.conf")
Metadata = {
    "Name"        : "ASNMeta",
    "Version"     : "1.0",
    "Description" : "./README.md",
    "Copyright"   : "Copyright 2016 Holmes Group LLC",
    "License"     : "./LICENSE"
}

def ASNMetaRun(ipaddress):
    asninfo = gatherasn.GatherASN(ipaddress,
                                    Config.asnmeta.dns_server, 
                                    Config.asnmeta.asn_ipv4_query, 
                                    Config.asnmeta.asn_ipv6_query,
                                    Config.asnmeta.asn_peer_query,
                                    Config.asnmeta.asn_name_query)
    
    asninfo.query_asn_origin()

    if asninfo.get_ip_version() == 4:
        asninfo.query_asn_peer()

    if asninfo.get_asn_number():
        asninfo.query_asn_name('AS{}'.format(asninfo.get_asn_number()))

    return asninfo.get_all_known_data()


class ASNMetaProcess(tornado.web.RequestHandler):
    def get(self):
        try:
            ipaddress = self.get_argument('obj', strip=False)
            data = ASNMetaRun(ipaddress)
            self.write(data)
        except tornado.web.MissingArgumentError:
            raise tornado.web.HTTPError(400)
        except gatherasn.IPTypeError:
            raise tornado.web.HTTPError(400)
        except gatherasn.IPFormatError:
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
            name        = str(Metadata["Name"]).replace("\n", "<br>"),
            version     = str(Metadata["Version"]).replace("\n", "<br>"),
            description = str(Metadata["Description"]).replace("\n", "<br>"),
            license     = str(Metadata["License"]).replace("\n", "<br>")
        )
        self.write(info)


class ASNApp(tornado.web.Application):
    def __init__(self):
        for key in ["Description", "License"]:
            fpath = Metadata[key]
            if os.path.isfile(fpath):
                with open(fpath) as file:
                    Metadata[key] = file.read()

        handlers = [
            (r'/', Info),
            (r'/analyze/', ASNMetaProcess),
            #(r'/asnmeta/((?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$)', ASNMetaProcess)
        ]
        settings = dict(
            template_path=path.join(path.dirname(__file__), 'templates'),
            static_path=path.join(path.dirname(__file__), 'static'),
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        self.engine = None


def main():
    server = tornado.httpserver.HTTPServer(ASNApp())
    server.listen(Config.settings.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
