import os
import tempfile
import shutil


class Meta():
	needed_meta_data = ["ServiceName", "ServiceVersion", "ServiceConfig", "ObjectCategory", "ObjectType"]

	"""
	Class for storing metadata for a service.
	Metadata are read from a file with lines of the form:
		key = value
	"""
	def __init__(self, cfg="META"):
		self.data = dict()
		f = open(cfg)
		for line in f:
			if(line.strip() == ""):
				continue
			l = line.split("=")
			if len(l) == 2:
				key = l[0].strip()
				value = l[1].strip()
				self.data[key] = value
			else:
				print("%s malformed. Ignoring line: %s" % (cfg, line))
				#exit(-1)
		for needed in Meta.needed_meta_data:
			if self.data.get(needed) is None:
				print("%s is not configured in %s!" % (needed, cfg))

	def getServiceName(self):
		return self.data["ServiceName"]
	def getServiceVersion(self):
		return self.data["ServiceVersion"]
	def getServiceConfig(self):
		return self.data["ServiceConfig"]
	def getObjectCategory(self):
		return self.data["ObjectCategory"]
	def getObjectType(self):
		return self.data["ObjectType"]



class TempAnalysisFile(object):
    """
    Temporary Analysis File class.
    """

    def __init__(self, obj):
        self.obj = obj
        print(obj)

    def __enter__(self):
        """
        Create the temporary file on disk.
        """

        tempdir = tempfile.mkdtemp()
        self.directory = tempdir
        tfile = os.path.join(tempdir, self.obj)
        with open(tfile, "wb") as f:
            f.write(open(self.obj).read())
        return tfile

    def __exit__(self, type, value, traceback):
        """
        Cleanup temporary file on disk.
        """

        if os.path.isdir(self.directory):
            shutil.rmtree(self.directory)