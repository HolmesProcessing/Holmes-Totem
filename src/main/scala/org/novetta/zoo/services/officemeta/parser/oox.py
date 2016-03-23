"""
Totem officemeta service - OOXML/MOX file parser

TODO:
 - submit contained files to the analysis queue (once Totem supports this)
 - find a better solution than lstrip for paths in a zipfile if possible
 - improve performance, currently multiple looping over same data - unnecessary?
"""

# imports for the parser
import zipfile
import ziphelper
from xmlhelper import xml2obj
import re
from defusedxml.cElementTree import fromstring as parseXML
import io

# import for result compilation
from library.services import ServiceResultSet

# determine if it's an ooxml file (equals zip file)
def match (data):
    return zipfile.is_zipfile(io.BytesIO(data))


# ooxml specifications
re_namespace = re.compile("^({.*})?(.*)$")
ooxml_namespaces = {
    "types": "http://schemas.openxmlformats.org/package/2006/content-types"
}
ooxml_document_identifier = "{{{:s}}}Types".format(ooxml_namespaces["types"])

ooxml_filetypes = {
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"
}

ooxml_parts = {
    "shared": {
        "Extended File Properties":     "application/vnd.openxmlformats-officedocument.extended-properties+xml",
        "File Properties":              "application/vnd.openxmlformats-package.core-properties+xml",
        "Relationships":                "application/vnd.openxmlformats-package.relationships+xml",
        "Theme":                        "application/vnd.openxmlformats-officedocument.theme+xml",
    },
    "docx": {
        "Comment":                      "application/vnd.openxmlformats-officedocument.wordprocessingml.comment+xml",               # ?
        "Document Settings":            "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml",
        "Endnotes":                     "application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml",              # ?
        "Font Table":                   "application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml",
        "Footer":                       "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml",                # ?
        "Footnotes":                    "application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml",             # ?
        "Glossary":                     "application/vnd.openxmlformats-officedocument.wordprocessingml.glossary+xml",              # ?
        "Header":                       "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml",                # ?
        "Main Document":                "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        "Numbering Definitions":        "application/vnd.openxmlformats-officedocument.wordprocessingml.numberingDefinitions+xml",  # ?
        "Style Definitions":            "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
        "Web Settings":                 "application/vnd.openxmlformats-officedocument.wordprocessingml.webSettings+xml",           # ?
    },
    "xlsx": {
        "Calculation Chain":            "application/vnd.openxmlformats-officedocument.spreadsheetml.calculationChain+xml",          # ?
        "Chartsheet":                   "application/vnd.openxmlformats-officedocument.spreadsheetml.chartsheet+xml",                # ?
        "Comment":                      "application/vnd.openxmlformats-officedocument.spreadsheetml.comment+xml",                   # ?
        "Connections":                  "application/vnd.openxmlformats-officedocument.spreadsheetml.connections+xml",               # ?
        "Custom Property":              "application/vnd.openxmlformats-officedocument.spreadsheetml.customProperty+xml",            # ?
        "Customer XML Mappings":        "application/vnd.openxmlformats-officedocument.spreadsheetml.customerXmlMappings+xml",       # ?
        "Dialogsheet":                  "application/vnd.openxmlformats-officedocument.spreadsheetml.dialogsheet+xml",               # ?
        "Drawing":                      "application/vnd.openxmlformats-officedocument.spreadsheetml.drawing+xml",
        "External Workbook Reference":  "application/vnd.openxmlformats-officedocument.spreadsheetml.externalWorkbookReference+xml", # ?
        "Metadata":                     "application/vnd.openxmlformats-officedocument.spreadsheetml.metadata+xml",                  # ?
        "Pivot Table":                  "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotTable+xml",                # ?
        "Pivot Table Cache Definition": "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotTableCacheDefinition+xml", # ?
        "Pivot Table Cache Records":    "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotTableCacheRecords+xml",    # ?
        "Query Table":                  "application/vnd.openxmlformats-officedocument.spreadsheetml.queryTable+xml",                # ?
        "Shared String Table":          "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml",
        "Shared Workbook Revision Log": "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedWorkbookRevisionLog+xml", # ?
        "Shared Workbook User Data":    "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedWorkbookUserData+xml",    # ?
        "Single Cell Table Definition": "application/vnd.openxmlformats-officedocument.spreadsheetml.singleCellTableDefinition+xml", # ?
        "Styles":                       "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml",                    # ?
        "Table Definition":             "application/vnd.openxmlformats-officedocument.spreadsheetml.tableDefinition+xml",           # ?
        "Volatile Dependencies":        "application/vnd.openxmlformats-officedocument.spreadsheetml.volatileDependencies+xml",      # ?
        "Workbook":                     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
        "Worksheet":                    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml",
    },
    "pptx": {
        "Comments Authors":             "application/vnd.openxmlformats-officedocument.presentationml.commentsAuthors+xml",         # ?
        "Comments":                     "application/vnd.openxmlformats-officedocument.presentationml.comments+xml",                # ?
        "Handout Master":               "application/vnd.openxmlformats-officedocument.presentationml.handoutMaster+xml",           # ?
        "Notes Master":                 "application/vnd.openxmlformats-officedocument.presentationml.notesMaster+xml",             # ?
        "Notes Slide":                  "application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml",              # ?
        "Presentation":                 "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
        "Presentation Properties":      "application/vnd.openxmlformats-officedocument.presentationml.presentationProperties+xml",  # ?
        "Slide":                        "application/vnd.openxmlformats-officedocument.presentationml.slide+xml",
        "Slide Layout":                 "application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml",
        "Slide Master":                 "application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml",
        "Slide Synchronization Data":   "application/vnd.openxmlformats-officedocument.presentationml.slideSynchronizationData+xml",# ?
        "User-Defined Tags":            "application/vnd.openxmlformats-officedocument.presentationml.userDefinedTags+xml",         # ?
        "View Properties":              "application/vnd.openxmlformats-officedocument.presentationml.viewProperties+xml",          # ?
    }
}


class Parser (object):
    
    def __init__(self, filedata, verbose=False):
        # settings:
        self.data = io.BytesIO(filedata)
        self.verbose = verbose
        self.zip = None
        # format and contained files:
        self.filetype = ""
        self.contained_files_list = []
        self.contained_files = []
        self.parts = {}
        self.named_parts = {}
        # file type
        self.is_docx = False
        self.is_xlsx = False
        self.is_pptx = False
        # results
        self.results = {}
    
    
    def analyzeZip(self):
        self.contained_files_list = self.zip.namelist()
        for filename in self.contained_files_list:
            self.contained_files.append(ziphelper.fileinfo(self.zip, filename))
    
    
    def parseContentTypesXML(self):
        file = self.zip.open("[Content_Types].xml")
        xml = parseXML(file.read())
        file.close()
        if xml.tag != ooxml_document_identifier:
            xml = xml.find("types:Types", ooxml_namespaces)
            if not xml:
                return None
        
        # register all parts
        for override in xml.findall("types:Override", ooxml_namespaces):
            if "ContentType" in override.attrib and "PartName" in override.attrib:
                if not (override.attrib["ContentType"] in self.parts):
                    self.parts[override.attrib["ContentType"]] = []
                self.parts[override.attrib["ContentType"]].append(override.attrib["PartName"].lstrip("/"))
                # TODO: why is the absolute path not accepted by pythons zip extension?
        return True
    
    
    def examineFiletype(self):
        docx = (ooxml_filetypes["docx"] in self.parts)
        xlsx = (ooxml_filetypes["xlsx"] in self.parts)
        pptx = (ooxml_filetypes["pptx"] in self.parts)
        self.valid = (docx and not xlsx and not pptx) or (xlsx and not docx and not pptx) or (pptx and not docx and not xlsx)
        self.is_docx = docx
        self.is_xlsx = xlsx
        self.is_pptx = pptx
        self.filetype = []
        if docx:
            self.filetype.append("Word")
        if xlsx:
            self.filetype.append("Excel")
        if pptx:
            self.filetype.append("Powerpoint")
        self.filetype = "|".join(self.filetype)
    
    
    def getParts(self, filetype):
        partkeys = ooxml_parts[filetype]
        answer = {}
        for name in partkeys:
            if partkeys[name] in self.parts:
                answer[name] = self.parts[partkeys[name]]
        return answer
    
    
    def parsePart(self, partname, category="SummaryInformation", max_depth=20):
        results = []
        if partname in self.named_parts:
            for part in self.named_parts[partname]:
                file = self.zip.open(part)
                xml = parseXML(file.read())
                file.close()
                im_results = {}
                children = xml2obj(xml,max_depth)["children"]
                for child in children:
                    im_results[child["tag"]] = child
                if im_results:
                    results.append(im_results)
        if results:
            if not (category in self.results):
                self.results[category] = {}
            self.results[category][partname] = results
    
    
    def loadProperties(self):
        # standard shared properties
        self.named_parts = self.getParts("shared")
        self.parsePart("File Properties")
        self.parsePart("Extended File Properties")
        self.parsePart("Relationships","Relationships")
        self.parsePart("Theme","Theme")
        
        # format specific interesting properties
        if self.is_docx:
            self.named_parts.update(self.getParts("docx"))
            self.parsePart("Style Definitions","Style Definitions")
            self.parsePart("Document Settings","Document Settings")
        
        if self.is_xlsx:
            self.named_parts.update(self.getParts("xlsx"))
            self.parsePart("Styles","Styles")
        
        if self.is_pptx:
            self.named_parts.update(self.getParts("pptx"))
    
    
    def parse(self):
        # must be a zip
        try:
            self.zip = zipfile.ZipFile(self.data)
        except zipfile.BadZipFile:
            return None
        
        # retrieve contained files
        self.analyzeZip()
        
        # retrieve root file
        if not ("[Content_Types].xml" in self.contained_files_list):
            return False
        if not self.parseContentTypesXML():
            return False
        
        # retrieve filetype
        self.examineFiletype()
        
        # examine document properties
        self.loadProperties()
        
        # clean up
        self.zip.close()
        
        return True
    
    
    def make_dictionary(self):
        result = ServiceResultSet()
        result.add("format","ooxml")
        result.add("type",self.filetype)
        result.add("version","Microsoft Office Open XML 2007-2013")
        for category in self.results:
            for partname in self.results[category]:
                x = self.results[category][partname]
                if len(x) == 1:
                    x = x[0]
                elif len(x) > 1:
                    r = []
                    for item in x:
                        if isinstance(item, list):
                            r += [y for y in item]
                        elif isinstance(item, dict):
                            r += [item[y] for y in item]
                        else:
                            r.append(item)
                    x = r
                result.add("doc_meta", category, partname, x)
        for file in self.contained_files:
            result.add("directory",file["filename"],file)
        return result.data
