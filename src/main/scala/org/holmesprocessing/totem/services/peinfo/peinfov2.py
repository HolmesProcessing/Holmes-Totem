import pefile
import json

import os
from os import path
import traceback

import tornado
from tornado import web, httpserver, ioloop

import time

# reading configuration file

Metadata = {
        "Name"  :   "PEInfo",
        "Version" : "2.0",
        "Description" : "./README.md",
        "Copyright": "Copyright 2017 Holmes Group LLC",
        "License" : "./LICENSE"
    }

def ServiceConfig(filename):
    configPath = filename
    try:
        config = json.loads(open(configPath).read())
        return config
    except FileNotFoundError:
        raise tornado.web.HTTPError(500)

Config = ServiceConfig("./service.conf")

def retrieve_flags(flag_dict, flag_filter):
    return [(f[0], f[1]) for f in list(flag_dict.items()) if isinstance(f[0], (str, bytes)) and f[0].startswith(flag_filter)]

def _headers(exe):
    headers = {}
    headers['DOS_HEADER'] = exe.DOS_HEADER.dump_dict()
    headers['NT_HEADERS'] = exe.NT_HEADERS.dump_dict()
    headers['FILE_HEADER'] = exe.FILE_HEADER.dump_dict()

    if hasattr(exe, 'OPTIONAL_HEADER') and exe.OPTIONAL_HEADER is not None:
        headers['OPTIONAL_HEADER'] = exe.OPTIONAL_HEADER.dump_dict()
    return headers

def _sections(exe):
    sections_list = []
    sections_dump = {}
    for section in exe.sections:
        sections_dump = section.dump_dict()
        sections_dump['entrophy'] = section.get_entropy()
        sections_dump['md5'] = section.get_hash_md5()
        sections_dump['SHA-1'] = section.get_hash_sha1()
        sections_dump['SHA-256'] = section.get_hash_sha256()
        sections_dump['SHA-512'] = section.get_hash_sha512()
        sections_list.append(sections_dump)
    return sections_list

def _dll_characteristics_flags(exe):
    data = []
    dll_characteristics_flags = retrieve_flags(pefile.DLL_CHARACTERISTICS, 'IMAGE_DLLCHARACTERISTICS_') # access the global variable from pefile
    for flag in dll_characteristics_flags:
        if getattr(exe.OPTIONAL_HEADER, flag[0]):
            data.append(flag[0])
    return data

def _dataDirectories(exe):
    directories = []
    for idx in range(len(exe.OPTIONAL_HEADER.DATA_DIRECTORY)):
        directory = exe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
        directories.append(directory.dump_dict())
    return directories

def _directory_bound_imports(exe):
    data = list()
    for bound_imp_desc in exe.DIRECTORY_ENTRY_BOUND_IMPORT:
        bound_imp_desc_dict = dict()
        data['Bound imports'].append(bound_imp_desc_dict)

        bound_imp_desc_dict.update(bound_imp_desc.struct.dump_dict())
        bound_imp_desc_dict['DLL'] = bound_imp_desc.name

        for bound_imp_ref in bound_imp_desc.entries:
            bound_imp_ref_dict = dict()
            bound_imp_ref_dict.update(bound_imp_ref.struct.dump_dict())
            bound_imp_ref_dict['DLL'] = bound_imp_ref.name

    return data

def _imported_symbols(exe):
    data = list()
    for module in exe.DIRECTORY_ENTRY_IMPORT:
        import_list = []
        data.append(import_list)
        import_list.append(module.struct.dump_dict())
        for symbol in module.imports:
            symbol_dict = {}
            if symbol.import_by_ordinal is True:
                symbol_dict['DLL'] = module.dll
                symbol_dict['Ordinal'] = symbol.ordinal
            else:
                symbol_dict['DLL'] = module.dll
                symbol_dict['Name'] = symbol.name
                symbol_dict['Hint'] = symbol.hint

            if symbol.bound:
                symbol_dict['Bound'] = symbol.bound

    return data

def _relocations_directory(exe):
    data = list()
    for base_reloc in exe.DIRECTORY_ENTRY_BASERELOC:
        base_reloc_list = list()
        data.append(base_reloc_list)
        base_reloc_list.append(base_reloc.struct.dump_dict())
        for reloc in base_reloc.entries:
            reloc_dict = dict()
            base_reloc_list.append(reloc_dict)
            reloc_dict['RVA'] = reloc.rva
            try:
                reloc_dict['Type'] = pefile.RELOCATION_TYPE[reloc.type][16:]
            except KeyError:
                reloc_dict['Type'] = reloc.type
    return data

def _debug_Directory(exe):
    data = list()
    for dbg in exe.DIRECTORY_ENTRY_DEBUG:
        dbg_dict = dict()
        data.append(dbg_dict)
        dbg_dict.update(dbg.struct.dump_dict())
        dbg_dict['Type'] = pefile.DEBUG_TYPE.get(dbg.struct.Type, dbg.struct.Type)
    return data

def _resources_data_entry(exe):
    data = list()
    data.append(exe.DIRECTORY_ENTRY_RESOURCE.struct.dump_dict())

    for resource_type in exe.DIRECTORY_ENTRY_RESOURCE.entries:
        resource_type_dict = dict()

        if resource_type.name is not None:
            resource_type_dict['Name'] = resource_type.name
        else:
            resource_type_dict['Id'] = (
                resource_type.struct.Id, pefile.RESOURCE_TYPE.get(resource_type.struct.Id, '-'))

        resource_type_dict.update(resource_type.struct.dump_dict())
        data.append(resource_type_dict)

        if hasattr(resource_type, 'directory'):
            directory_list = list()
            directory_list.append(resource_type.directory.struct.dump_dict())
            data.append(directory_list)

            for resource_id in resource_type.directory.entries:
                resource_id_dict = dict()

                if resource_id.name is not None:
                    resource_id_dict['Name'] = resource_id.name
                else:
                    resource_id_dict['Id'] = resource_id.struct.Id

                resource_id_dict.update(resource_id.struct.dump_dict())
                directory_list.append(resource_id_dict)

                if hasattr(resource_id, 'directory'):
                    resource_id_list = list()
                    resource_id_list.append(resource_id.directory.struct.dump_dict())
                    directory_list.append(resource_id_list)

                    for resource_lang in resource_id.directory.entries:
                        if hasattr(resource_lang, 'data'):
                            resource_lang_dict = dict()
                            resource_lang_dict['LANG'] = resource_lang.data.lang
                            resource_lang_dict['SUBLANG'] = resource_lang.data.sublang
                            resource_lang_dict['LANG_NAME'] = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
                            resource_lang_dict['SUBLANG_NAME'] = pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang)
                            resource_lang_dict.update(resource_lang.struct.dump_dict())
                            resource_lang_dict.update(resource_lang.data.struct.dump_dict())
                            resource_id_list.append(resource_lang_dict)
                    if hasattr(resource_id.directory, 'strings') and resource_id.directory.strings:
                        for idx, res_string in list(resource_id.directory.strings.items()):
                            resource_id_list.append(res_string.encode(
                                    'unicode-escape',
                                    'backslashreplace').decode(
                                        'ascii'))       
    return data

def _version_Information(exe):
    version_info = []
    version_info.append(exe.VS_VERSIONINFO.dump_dict())

    if hasattr(exe, 'VS_FIXEDFILEINFO'):
        version_info.append(exe.VS_FIXEDFILEINFO.dump_dict())

    return version_info

def _export_directory(exe):
    data = list()
    data.append(exe.DIRECTORY_ENTRY_EXPORT.struct.dump_dict())
    for export in exe.DIRECTORY_ENTRY_EXPORT.symbols:
        export_dict = dict()
        if export.address is not None:
            export_dict.update({'Ordinal': export.ordinal, 'RVA': export.address, 'Name': export.name})
            if export.forwarder:
                export_dict['forwarder'] = export.forwarder
        data.append(export_dict)
    return data

def _delay_import_directory(exe):
    data = list()
    for module in exe.DIRECTORY_ENTRY_DELAY_IMPORT:
        module_list = list()
        data['Delay Imported symbols'].append(module_list)
        module_list.append(module.struct.dump_dict())

        for symbol in module.imports:
            symbol_dict = dict()
            if symbol.import_by_ordinal is True:
                symbol_dict['DLL'] = module.dll
                symbol_dict['Ordinal'] = symbol.ordinal
            else:
                symbol_dict['DLL'] = module.dll
                symbol_dict['Name'] = symbol.name
                symbol_dict['Hint'] = symbol.hint

            if symbol.bound:
                symbol_dict['Bound'] = symbol.bound
            module_list.append(symbol_dict)

    return data

def PEInfoRun(obj):
    data = {}
    try:
        pe = pefile.PE(obj)
    except pefile.PEFormatError as e:
        return e
  
    data["HEADERS"] = _headers(pe)
    data["Sections"] = _sections(pe)

    # data["DllCharacteristics"] = _dll_characteristics_flags(pe)
    
    data["directories"] = {}
    if (hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') ):
         data["directories"] = _dataDirectories(pe)

    data["VersionInfo"] = {}
    if hasattr(pe, 'VS_VERSIONINFO'):
         data["VersionInfo"] = _version_Information(pe)

    data['Exports'] = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        data['Exports'] = _export_directory(pe)

    data['Importedsymbols'] = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        data['Importedsymbols'] = _imported_symbols(pe)
        
    data['BoundImports'] = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
        data['BoundImports'] = _directory_bound_imports(pe)

    data['DelayImportedSymbols'] = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        data['DelayImportedSymbols'] = _delay_import_directory(pe)

    data['ResourceDirectory'] = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            data['ResourceDirectory'] = _resources_data_entry(pe)
            
    data['TLS'] = {}
    if ( hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS and pe.DIRECTORY_ENTRY_TLS.struct ):
            data['TLS'] = pe.DIRECTORY_ENTRY_TLS.struct.dump_dict()

    data['LOAD_CONFIG'] = {}
    if ( hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') and pe.DIRECTORY_ENTRY_LOAD_CONFIG and pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct ):
        data['LOAD_CONFIG'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.dump_dict()

    data['DebugInfo'] = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        data['DebugInfo'] = _debug_Directory(pe)

    data['BaseRelocations'] = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        data['BaseRelocations'] = _relocations_directory(pe)

    return data

class PEInfoProcess(tornado.web.RequestHandler):
    def get(self):
        try:
            filename = self.get_argument("obj", strip=False)
            fullPath = os.path.join('/tmp', filename)
            start_time = time.time()
            data = PEInfoRun(fullPath)
            self.write(data)
            #print("--- Done analysing Total time taken %s ms --- \n" % ((time.time() - start_time)*1000))
        except tornado.web.MissingArgumentError:
            raise tornado.web.HTTPError(400)
        except TypeError as e:
            raise tornado.web.HTTPError(500)
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
                name = str(Metadata["Name"]).replace("\n", "<br>"),
                version = str(Metadata["Version"]).replace("\n", "<br>"),
                description = str(Metadata["Description"]).replace("\n", "<br>"),
                license = str(Metadata["License"]).replace("\n", "<br>")
        )
        self.write(info)

class PEApp(tornado.web.Application):
    def __init__(self):
        for key in ["Description", "License"]:
            fpath = Metadata[key]
            if os.path.isfile(fpath):
                with open(fpath) as file:
                    Metadata[key] = file.read()

        handlers = [
                (r'/', Info),
                (r'/analyze/', PEInfoProcess),
            ]
        settings = dict(
            template_path = path.join(path.dirname(__file__), 'templates'),
            static_path = path.join(path.dirname(__file__), 'static'),
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        self.engine = None

def main():
    server = tornado.httpserver.HTTPServer(PEApp())
    server.listen(Config["settings"]["port"])
    try:
        tornado.ioloop.IOLoop.current().start()
    except KeyboardInterrupt:
        tornado.ioloop.IOLoop.current().stop()

if __name__ == '__main__':
    main()
