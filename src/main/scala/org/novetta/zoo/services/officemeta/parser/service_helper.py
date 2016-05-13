# parsers
import ole, oox, mso, xml

# error class
from error import OfficeMetaError


class ServiceHelper (object):
    def __init__ (self, filename):
        with open(filename, "rb") as officefile:
            self.data = officefile.read()
        if not self.data:
            raise OfficeMetaError(500, "Could not read file")
        
    def parse_office_doc(self):
        # unpack first if activemime/mso
        if mso.match(self.data):
            self.data = mso.extract(self.data)
        
        if ole.match(self.data):
            parser = ole.Parser(self.data)
        elif oox.match(self.data):
            parser = oox.Parser(self.data)
        else:
            # last chance, plain text office 2003 format
            parser = xml.Parser(self.data)
        if not parser.parse():
            raise OfficeMetaError(500, "Could not parse file as an office document")
        return parser.make_dictionary()
