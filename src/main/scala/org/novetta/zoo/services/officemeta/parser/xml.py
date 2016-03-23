"""
Totem officemeta service - xml-format file parser
"""

# imports for parsing as a word 2003 office document
from defusedxml.cElementTree import fromstring as parseXML
from xmlhelper import xml2obj, split_tag
import binascii
import hashlib

# import for result compilation
from library.services import ServiceResultSet

# static data
xml_filetypes = {
    "http://schemas.microsoft.com/office/word/2003/wordml": "word",
    
}

#
class Parser (object):
    
    def __init__ (self, filedata):
        self.data = filedata
        # result data
        self.filetype = ""
        self.properties = []
        self.custom_properties = []
        self.document_settings = []
        self.fonts = []
        self.styles = []
        self.embedded_files = []

    def parse(self):
        try:
            # parse xml
            xml = parseXML(self.data)
            
            # get filetype
            (namespace, tag) = split_tag(xml.tag)
            if tag=="wordDocument":
                self.filetype = "Word"
            if tag=="Workbook":
                self.filetype = "Excel"
            
            # get all the properties
            DOCUMENT_PROPERTIES = "{urn:schemas-microsoft-com:office:office}DocumentProperties"
            CUSTOM_PROPERTIES   = "{urn:schemas-microsoft-com:office:office}CustomDocumentProperties"
            DOCUMENT_SETTINGS   = "{{{:s}}}docPr".format(namespace)
            
            for propContainer in xml.findall(DOCUMENT_PROPERTIES):
                for prop in propContainer:
                    self.properties.append(xml2obj(prop))
            for propContainer in xml.iter(CUSTOM_PROPERTIES):
                for prop in propContainer:
                    self.custom_properties.append(xml2obj(prop))
            for propContainer in xml.iter(DOCUMENT_SETTINGS):
                for prop in propContainer:
                    self.document_settings.append(xml2obj(prop))
            
            # get fonts and styles
            FONTS  = "{{{:s}}}fonts".format(namespace)
            STYLES = "{{{:s}}}styles".format(namespace)
            
            for fontContainer in xml.iter(FONTS):
                for font in fontContainer:
                    self.fonts.append(xml2obj(font))
            for styleContainer in xml.iter(STYLES):
                for style in styleContainer:
                    self.styles.append(xml2obj(style))
            
            # get embedded files
            BINDATA = "{{{:s}}}binData".format(namespace)
            
            for binData in xml.iter(BINDATA):
                obj = xml2obj(binData)
                bin = binascii.a2b_base64(obj["text"])
                md5 = hashlib.md5(bin).hexdigest()
                del(obj["text"])
                obj["md5"] = md5
                self.embedded_files.append(obj)
            return True
        except:
            return False
    
    def make_dictionary (self):
        result = ServiceResultSet()
        
        for prop in self.properties:
            result.add("doc_meta","SummaryInformation",prop["tag"],prop)
        for prop in self.custom_properties:
            result.add("doc_meta","SummaryInformation",prop["tag"],prop)
        for prop in self.document_settings:
            result.add("doc_meta","DocumentSettings",prop["tag"],prop)
        for font in self.fonts:
            result.add("doc_meta","Fonts",font["tag"],font)
        for style in self.styles:
            result.add("doc_meta","Styles",style["tag"],style)
        for file in self.embedded_files:
            result.add("directory",file["attributes"]["name"]["value"],file)
        
        result.add("format","xml")
        result.add("type",self.filetype)
        result.add("version","Microsoft Office 2003")
        
        return result.data
