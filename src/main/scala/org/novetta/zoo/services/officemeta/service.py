# imports for tornado
import tornado.web, tornado.httpserver, tornado.ioloop, tornado.options

# imports for officemeta
from office_meta      import OfficeParser, OfficeMetaError
from library.services import ServiceResultSet, ServiceConfig
import binascii
import traceback
import os


# get config and init Tornado
Config = ServiceConfig("./service.conf")
tornado.options.define("port", default=int(Config.settings.port,10),
    help="port to run", type=int)


class OfficeMetaProcess(tornado.web.RequestHandler):
    def get(self, filename):
        resultset = ServiceResultSet()
        try:
            # read file
            fullPath = os.path.join('/tmp/', filename)
            data     = False
            with open(fullPath, "rb") as file:
                data = file.read()
            if not data:
                raise OfficeMetaError(500,"Could not read file")
            
            office_magic = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
            if not data.startswith(office_magic):
                raise OfficeMetaError(500,"Not a valid office document")
            
            # init parser
            oparser  = OfficeParser(data)
            oparser.parse_office_doc()
            
            # gather results
            added_files = []
            if not oparser.office_header.get('maj_ver'):
                raise OfficeMetaError(500,"Could not parse file as an office document")
            
            resultset.add("office_header", '%d.%d' %
                (oparser.office_header.get('maj_ver'), oparser.office_header.get('min_ver')))
            
            for curr_dir in oparser.directory:
                directory = {
                    'md5':          curr_dir.get('md5', ''),
                    'size':         curr_dir.get('stream_size', 0),
                    'mod_time':     oparser.timestamp_string(curr_dir['modify_time'])[1],
                    'create_time':  oparser.timestamp_string(curr_dir['create_time'])[1],
                }
                name = curr_dir['norm_name'].decode('ascii', errors='ignore')
                resultset.add("directory",name,directory)
                
                if Config.settings.save_streams == 1 and 'data' in curr_dir:
                    # TODO: how to do this with Totem?
                    # handle_file(name, curr_dir['data'], obj.source,
                    #             related_id=str(obj.id),
                    #             campaign=obj.campaign,
                    #             method=self.name,
                    #             relationship=RelationshipTypes.CONTAINED_WITHIN,
                    #             user=self.current_task.username)
                    # stream_md5 = hashlib.md5(curr_dir['data']).hexdigest()
                    # added_files.append((name, stream_md5))
                    pass
            
            for prop_list in oparser.properties:
                for prop in prop_list['property_list']:
                    prop_summary = oparser.summary_mapping.get(binascii.unhexlify(prop['clsid']), None)
                    prop_name = prop_summary.get('name', 'Unknown')
                    for item in prop['properties']['properties']:
                        result = {
                            'name':             item.get('name', 'Unknown'),
                            'value':            item.get('date', item['value']),
                            'result':           item.get('result', ''),
                        }
                        resultset.add('doc_meta', prop_name, result)
            
            for f in added_files:
                resultset.add("file_added", f[0], {'md5': f[1]})
            
            self.write({"result": resultset.data})
        
        except OfficeMetaError as ze:
            self.set_status(ze.status, str(ze.error))
            self.write("")
        except Exception as e:
            self.set_status(500, str(e))
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
            license     = str(Config.metadata.license).replace("\n", "<br>")
        )
        self.write(info)


class ServiceApp(tornado.web.Application):
    def __init__(self):
        handlers = [
            (Config.settings.infourl + r'', Info),
            (Config.settings.analysisurl + r'/([a-zA-Z0-9\-\.]*)', OfficeMetaProcess),
        ]
        settings = dict(
            template_path=os.path.join(os.path.dirname(__file__), 'templates'),
            static_path=os.path.join(os.path.dirname(__file__), 'static'),
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        self.engine = None


def main():
    tornado.options.parse_command_line()
    server = tornado.httpserver.HTTPServer(ServiceApp())
    server.listen(tornado.options.options.port)
    print("starting the office_meta worker on port {}".format(
        tornado.options.options.port))
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
