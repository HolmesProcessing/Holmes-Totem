# imports for PEInfo
from __future__ import division

# imports for tornado
import tornado
from tornado import web, httpserver

# imports for logging
import traceback
import os
from os import path

# imports for PEInfo
import pefile
import bitstring
import string
import bz2
import binascii
import hashlib
import logging
import struct
from time import localtime, strftime


def _get_pehash(self, exe):
    #image characteristics
    img_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Characteristics))
    #pad to 16 bits
    img_chars = bitstring.BitArray(bytes=img_chars.tobytes())
    img_chars_xor = img_chars[0:7] ^ img_chars[8:15]

    #start to build pehash
    pehash_bin = bitstring.BitArray(img_chars_xor)

    #subsystem -
    sub_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Machine))
    #pad to 16 bits
    sub_chars = bitstring.BitArray(bytes=sub_chars.tobytes())
    sub_chars_xor = sub_chars[0:7] ^ sub_chars[8:15]
    pehash_bin.append(sub_chars_xor)

    #Stack Commit Size
    stk_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfStackCommit))
    stk_size_bits = string.zfill(stk_size.bin, 32)
    #now xor the bits
    stk_size = bitstring.BitArray(bin=stk_size_bits)
    stk_size_xor = stk_size[8:15] ^ stk_size[16:23] ^ stk_size[24:31]
    #pad to 8 bits
    stk_size_xor = bitstring.BitArray(bytes=stk_size_xor.tobytes())
    pehash_bin.append(stk_size_xor)

    #Heap Commit Size
    hp_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfHeapCommit))
    hp_size_bits = string.zfill(hp_size.bin, 32)
    #now xor the bits
    hp_size = bitstring.BitArray(bin=hp_size_bits)
    hp_size_xor = hp_size[8:15] ^ hp_size[16:23] ^ hp_size[24:31]
    #pad to 8 bits
    hp_size_xor = bitstring.BitArray(bytes=hp_size_xor.tobytes())
    pehash_bin.append(hp_size_xor)

    #Section chars
    for section in exe.sections:
        #virutal address
        sect_va =  bitstring.BitArray(hex(section.VirtualAddress))
        sect_va = bitstring.BitArray(bytes=sect_va.tobytes())
        pehash_bin.append(sect_va)

        #rawsize
        sect_rs =  bitstring.BitArray(hex(section.SizeOfRawData))
        sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
        sect_rs_bits = string.zfill(sect_rs.bin, 32)
        sect_rs = bitstring.BitArray(bin=sect_rs_bits)
        sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
        sect_rs_bits = sect_rs[8:31]
        pehash_bin.append(sect_rs_bits)

        #section chars
        sect_chars =  bitstring.BitArray(hex(section.Characteristics))
        sect_chars = bitstring.BitArray(bytes=sect_chars.tobytes())
        sect_chars_xor = sect_chars[16:23] ^ sect_chars[24:31]
        pehash_bin.append(sect_chars_xor)

        #entropy calulation
        address = section.VirtualAddress
        size = section.SizeOfRawData
        raw = exe.write()[address+size:]
        if size == 0:
            kolmog = bitstring.BitArray(float=1, length=32)
            pehash_bin.append(kolmog[0:7])
            continue
        bz2_raw = bz2.compress(raw)
        bz2_size = len(bz2_raw)
        #k = round(bz2_size / size, 5)
        k = bz2_size / size
        kolmog = bitstring.BitArray(float=k, length=32)
        pehash_bin.append(kolmog[0:7])

    m = hashlib.sha1()
    m.update(pehash_bin.tobytes())
    output = m.hexdigest()
    return output


def PEInfoRun(obj):
    data = {}
    try:
        pe = pefile.PE(data=open(obj).read())
    except pefile.PEFormatError as e:
        # self._error("A PEFormatError occurred: %s" % e)
        return e
    data["pehash"] = _get_pehash(pe)
    data["pe_sections"] = _get_sections(pe)
    data["timestamp"] = _get_timestamp(pe)

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        data["imports"] = _get_imports(pe)

    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        data["exports"] = _get_exports(pe)


#working
    if hasattr(pe, 'VS_VERSIONINFO'):
        data["version_info"] = _get_version_info(pe)

    if hasattr(pe, 'VS_VERSIONINFO'):
        data["version_var"] = _get_version_var_info(pe)

    if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        data["debug"] = _get_debug_info(pe)

    if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        data["thread_local_storage"] = _get_tls_info(pe)

    # if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    #     self._dump_resource_data("ROOT",
    #                              pe.DIRECTORY_ENTRY_RESOURCE,
    #                              pe,
    #                              config['resource'])


    if callable(getattr(pe, 'get_imphash', None)):
        data["pehash"] = _get_imphash(pe)

    # not getting rich header

    return data


def _get_debug_info(self, pe):
    # woe is pefile when it comes to debug entries
    # we're mostly interested in codeview structures, namely NB10 and RSDS
    d = []
    try:
        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
            dbg_path = ""
            if hasattr(dbg.struct, "Type"):
                result = {
                     'MajorVersion': dbg.struct.MajorVersion,
                     'MinorVersion': dbg.struct.MinorVersion,
                     'PointerToRawData': hex(dbg.struct.PointerToRawData),
                     'SizeOfData': dbg.struct.SizeOfData,
                     'TimeDateStamp': dbg.struct.TimeDateStamp,
                     'TimeDateString': strftime('%Y-%m-%d %H:%M:%S', localtime(dbg.struct.TimeDateStamp)),
                     'Type': dbg.struct.Type,
                     'subtype': 'pe_debug',
                }
                # type 0x2 is codeview, though not any specific version
                # for other types we don't parse them yet
                # but sounds like a great project for an enterprising CRITs coder...
                if dbg.struct.Type == 0x2:
                    debug_offset = dbg.struct.PointerToRawData
                    debug_size = dbg.struct.SizeOfData
                    # ok, this probably isn't right, fix me
                    if debug_size < 0x200 and debug_size > 0:
                        # there might be a better way than __data__ in pefile to get the raw data
                        # i think that get_data uses RVA's, which this requires physical address
                        debug_data = pe.__data__[debug_offset:debug_offset + debug_size]
                        # now we need to check the codeview version,
                        # http://www.debuginfo.com/articles/debuginfomatch.html
                        # as far as I can tell the gold is in RSDS and NB10
                        if debug_data[:4] == "RSDS":
                            result.update({
                                'DebugSig': debug_data[0x00:0x04],
                                'DebugGUID': binascii.hexlify(debug_data[0x04:0x14]),
                                'DebugAge': struct.unpack('I', debug_data[0x14:0x18])[0],
                            })
                            if dbg.struct.SizeOfData > 0x18:
                                dbg_path = debug_data[0x18:dbg.struct.SizeOfData - 1].decode('UTF-8', errors='replace')
                                result.update({
                                    'DebugPath': "%s" % dbg_path,
                                    'result': "%s" % dbg_path,
                                })
                        if debug_data[:4] == "NB10":
                            result.update({
                                'DebugSig': debug_data[0x00:0x04],
                                'DebugTime': struct.unpack('I', debug_data[0x08:0x0c])[0],
                                'DebugAge': struct.unpack('I', debug_data[0x0c:0x10])[0],
                            })
                            if dbg.struct.SizeOfData > 0x10:
                                dbg_path = debug_data[0x10:dbg.struct.SizeOfData - 1].decode('UTF-8', errors='replace')
                                result.update({
                                    'DebugPath': "%s" % dbg_path,
                                    'result': "%s" % dbg_path,
                                })
            d.append(result)                
        return d
            #self._add_result('pe_debug', dbg_path, result)
    except Exception as e:
        return d


def _get_imphash(pe):
    imphash = pe.get_imphash()
    return imphash


def _get_imports(pe):
    d = []
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    name = imp.name
                else:
                    name = "%s#%s" % (entry.dll, imp.ordinal)

                d.append({"function": name, "dll": entry.dll})
        return d
    except Exception as e:
        return d


def _get_exports(pe):
    d = []
    try:
        for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            d.append({"function": entry.name})
        return d
    except Exception as e:
        return d


def _get_sections(pe):
    d = []
    for section in pe.sections:
        try:
            section_name = section.Name.decode('UTF-8', errors='replace')
            if section_name == "":
                section_name = "NULL"
            data = {
                    "section_name": section_name
                    "virt_address": hex(section.VirtualAddress),
                    "virt_size": section.Misc_VirtualSize,
                    "size": section.SizeOfRawData,
                    "md5": section.get_hash_md5(),
                    "entropy": section.get_entropy(),
            }
            d.append(data)
            #self._add_result('pe_section', section_name, data)
        except Exception as e:
            #self._parse_error("section info", e)
            continue
    return d


def _get_timestamp(pe):
    try:
        timestamp = pe.FILE_HEADER.TimeDateStamp
        time_string = strftime('%Y-%m-%dT%H:%M:%SZ', localtime(timestamp))
        return {'human_timestamp': time_string, "timestamp": timestamp}
    except Exception as e:
        return {}


# Thread local storage
def _get_tls_info(self, pe):
    d = []
    #self._info("TLS callback table listed at 0x%08x" % pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks)
    callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase

    # read the array of TLS callbacks until we hit a NULL ptr (end of array)
    idx = 0
    callback_functions = [ ]
    while pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0):
        callback_functions.append(pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0))
        idx += 1

    # if we start with a NULL ptr, then there are no callback functions
    if idx != 0:
        for idx, va in enumerate(callback_functions):
            va_string = "0x%08x" % va
            data = { "Callback Function": idx, "TLS Callback Function": va_string}
            d.append(data)
            #self._add_result('tls_callback', va_string, data)
    return d


def _get_version_info(pe):
    d = []
    if hasattr(pe, 'FileInfo'):
        try:
            for entry in pe.FileInfo:
                if hasattr(entry, 'StringTable'):
                    for st_entry in entry.StringTable:
                        for str_entry in st_entry.entries.items():
                            try:
                                value = str_entry[1].encode('ascii')
                                result = {
                                    'key':      str_entry[0],
                                    'value':    value,
                                }
                                d.append(result)
                            except:
                                value = str_entry[1].encode('ascii', errors='ignore')
                                raw = binascii.hexlify(str_entry[1].encode('utf-8'))
                                result = {
                                    'key':      str_entry[0],
                                    'value':    value,
                                    'raw':      raw,
                                }
                                d.append(result)
                            #result_name = str_entry[0] + ': ' + value[:255]
                            #self._add_result('version_info', result_name, result)
            return d
        except Exception as e:
            return d


def _get_version_var_info(pe):
    d = []
    if hasattr(pe, 'FileInfo'):
        try:                            
            if hasattr(entry, 'Var'):
                for var_entry in entry.Var:
                    if hasattr(var_entry, 'entry'):
                        for key in var_entry.entry.keys():
                            try:
                                value = var_entry.entry[key].encode('ascii')
                                result = {
                                    'key':      key,
                                    'value':    value,
                                }
                                d.append(result)
                            except:
                                value = var_entry.entry[key].encode('ascii', errors='ignore')
                                raw = binascii.hexlify(var_entry.entry[key])
                                result = {
                                    'key':      key,
                                    'value':    value,
                                    'raw':      raw,
                                }
                                d.append(result)
                            #result_name = key + ': ' + value
                            #self._add_result('version_var', result_name, result)
        return d
        except Exception as e:
            return d


class PEInfoProcess(tornado.web.RequestHandler):
    def get(self, filename):
        try:
            fullPath = os.path.join('/tmp/', filename)
            data = PEInfoRun(fullPath)
            print len(data)
            self.write(data)
        except Exception as e:
            self.write({"error": traceback.format_exc(e)})


class Info(tornado.web.RequestHandler):
    # Emits a string which describes the purpose of the analytics
    def get(self):
        description = """
Copyright 2015 Holmes Processing
Copyright (c) 2015, Adam Polkosnik, Team Cymru.  All rights reserved.

Source code distributed pursuant to license agreement.
PEhash computing code is from Team Cymru.
Wrapping into the CRITs module done by Adam Polkosnik.
Adjustments for TOTEM made by George Webster.
        """
        self.write(description)


class PEApp(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/', Info),
            (r'/peinfo/([a-zA-Z0-9\-]*)', PEInfoProcess),
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
    server = tornado.httpserver.HTTPServer(PEApp())
    server.listen(7705, address="127.0.0.1")
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()