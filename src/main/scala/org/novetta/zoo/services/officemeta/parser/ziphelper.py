"""
Totem officemeta service - zip helper library

TODO:
    - improve performance by manually going over the entries?
"""

# imports for generating/unpacking information
import struct
import hashlib

# helper function for hashing
def md5(afile, blocksize=65536):
    ahash = hashlib.md5()
    buf = afile.read(blocksize)
    while len(buf) > 0:
        ahash.update(buf)
        buf = afile.read(blocksize)
    return ahash.hexdigest()

# extra_header mapping
pkware_extra_headers = {
    0x0001:       "Zip64 extended information extra field",
    0x0007:       "AV Info",
    0x0008:       "Reserved for extended language encoding data (PFS)",
    0x0009:       "OS/2",
    0x000a:       "NTFS",
    0x000c:       "OpenVMS",
    0x000d:       "UNIX",
    0x000e:       "Reserved for file stream and fork descriptors",
    0x000f:       "Patch Descriptor",
    0x0014:       "PKCS#7 Store for X.509 Certificates",
    0x0015:       "X.509 Certificate ID and Signature for individual file",
    0x0016:       "X.509 Certificate ID for Central Directory",
    0x0017:       "Strong Encryption Header",
    0x0018:       "Record Management Controls",
    0x0019:       "PKCS#7 Encryption Recipient Certificate List",
    0x0065:       "IBM S/390 (Z390), AS/400 (I400) attributes uncompressed",
    0x0066:       "Reserved for IBM S/390 (Z390), AS/400 (I400) attributes - compressed",
    0x4690:       "POSZIP 4690 (reserved)"
}

# format time to "yyyy-mm-ddThh:mm:ssZ"
def timeformat (ziptime):
    return "{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}Z".format(
        ziptime[0], ziptime[1], ziptime[2], ziptime[3], ziptime[4], ziptime[5])

def get_extra_field_name (_id):
    if _id in pkware_extra_headers:
        return pkware_extra_headers[_id]
    else:
        return _id

# gather information about a file in a zip archive
def fileinfo (zip, filename):
    info         = zip.getinfo(filename)
    file         = zip.open(filename)
    extra_data   = info.extra
    extra_len    = len(extra_data)
    offset       = 0
    extra_fields = []
    
    while offset < extra_len:
        _id  = struct.unpack_from("<H",extra_data,offset+0)
        _len = struct.unpack_from("<H",extra_data,offset+2)
        data = extra_data[offset+4:offset+4+_len]
        extra_fields.append({
            "id": _id,
            "size": _len,
            "data": data,
            "name": get_extra_field_name(_id)
        })
        offset = offset + 4 + _len
    
    r = {
        "crc32":                info.CRC,
        "create_system":        info.create_system,
        "create_version":       info.create_version,
        "compressed_size":      info.compress_size,
        "compression_type":     info.compress_type,
        "external_attributes":  info.external_attr,
        "extra":                extra_fields,
        "extract_version":      info.extract_version,
        "filename":             info.filename,
        "filepath":             filename,
        "filesize":             info.file_size,
        "flag_bits":            info.flag_bits,
        "internal_attributes":  info.internal_attr,
        "last_modified":        timeformat(info.date_time),
        "md5":                  md5(file),
        "volume":               info.volume,
        "zip_comment":          info.comment
    }
    
    file.close()
    
    return r
