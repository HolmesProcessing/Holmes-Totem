"""
Totem officemeta service - mso/activemime file unpacker
"""

# imports for mso file parsing
import struct
import zlib
# import for bruteforcing if zlib block can't be directly found
import re
# error class
from error import OfficeMetaError


# is it a zlib compressed office file?
def match(data):
    return data.startswith("ActiveMime")


# extract using zlib python module
def extract (data):
    # First, attempt to get the compressed data offset from the header
    try:
        offset = struct.unpack_from('<H', data, offset=0x1E)[0] + 46
    except:
        pass # todo exception
    # fallback 0x32 (word) and 0x22a (excel)
    for start in (offset, 0x32, 0x22A):
        try:
            return zlib.decompress(data[start:])
        except:
            pass
    
    # nothing found on the given or the default offsets
    # zlib compressed blocks start with 0x78, bruteforce for any possible block
    for block in re.finditer(r'\x78',data):
        offset = block.start()
        try:
            return zlib.decompress(data[offset:])
        except:
            pass
    
    # either not found any zlib block offsets or no valid blocks, failed to extract
    raise OfficeMetaError(500, 'Unable to extract data from the activemime/mso file')
