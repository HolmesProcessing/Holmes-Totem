"""
Totem officemeta service - mso/activemime file parser

TODO:
    - implement
"""

# imports for mso file parsing
import io


# determine if it's a file in mso format (office2003)
def match(data):
    return data.startswith("ActiveMime")


#
class Parser (object):
    
    def __init__ (self, filedata):
        self.data = io.BytesIO(filedata)
    
    def parse (self):
        return None
        
