import sys, os, struct

class richLib():

	def __init__(self):
		self.files = []
		self.names = {}
		self.func_names_parsed = False

		self.publics = {}

	def parseElem(self, archive, off_start):
		file_identifier, file_mod_timestamp, file_owner_id, file_group_id, file_mode, \
		file_size, file_eof = struct.unpack("<16s12s6s6s8s10s2s", archive[off_start:off_start+60])

		file_header_start = off_start
		file_mod_timestamp = self.decFromBytes(file_mod_timestamp)
		file_owner_id = self.decFromBytes(file_owner_id)
		file_group_id = self.decFromBytes(file_group_id)
		file_mode = self.decFromBytes(file_mode)
		file_size = self.decFromBytes(file_size)
		file_data_start = off_start+60
		file_data = archive[file_data_start:file_data_start + file_size]

		#printFileHeader(file_identifier, file_header_start, file_mod_timestamp, file_owner_id, file_group_id, file_mode, file_size, file_data_start, file_eof)

		debug = False

		if (debug):
			print("-" * (60))
			print("Searching Next Header at: 0x%x (0x%x + 0x%x)" % (off_start, file_data_start, file_size))
			print("Searching Next Header at: %d (%d + %d)" % (off_start, file_data_start, file_size))
			print("Values at calculated Next Header location: ")
			print("First 2 Header Bytes: 0x%x 0x%x" % ( int(archive[file_header_start]), int(archive[file_header_start+1])))
			print("First 2 Data Bytes: 0x%x 0x%x" % ( int(archive[file_data_start]), int(archive[file_data_start+1])))
			print("Last 2 Data Bytes: 0x%x 0x%x" % ( int(archive[off_start-2]), int(archive[off_start-1])))
			print("-" * (60))
			print("")

		if (file_identifier == b'/               '):
			#list of exports i guess ?
			if (self.func_names_parsed == False):
				self.parseSpecial(file_data)
				self.func_names_parsed = True
			#else:
			#	self.parseSpecial2(file_data)

		if(file_identifier == b'//              '):
			#this should be the file / folder index
			self.parseSpecialIdx(file_data)

		#Handle special case of file_ident longer than 16 bytes which info is stored in another file in the archive
		#strip padding + leading /
		tmp_name = file_identifier.strip()[1:] 
		if(tmp_name.isdigit()):
			if(int(tmp_name) in self.names):
				#print(self.names[int(tmp_name)])
				file_identifier = self.names[int(tmp_name)]

		return ({
			'file_identifier': file_identifier,
			'file_header_start': file_header_start,
			'file_mod_timestamp': file_mod_timestamp,
			'file_owner_id': file_owner_id,
			'file_group_id': file_group_id,
			'file_mode': file_mode,
			'file_size': file_size,
			'file_data_start': file_data_start,
			'file_data': file_data
		})

	def parseLib(self, arg):
		#return True
		""" Basic AR format:
		struct {
			char 	file_identifier[16]; 		/* ASCII File Id */
			char	file_mod_timestamp[12]; 	/* Decimal Timestamp */
			char	file_owner_id[6];			/* Owner Id */
			char	file_group_id[6];			/* Group Id */
			char	file_mode[8];				/* File Mode */
			char	file_size[10];				/* File Size = Data range until next file starts */
			char	file_eof[2];				/* EOF signature */
		}
		"""

		dat = open(arg, 'rb').read()

		if dat[:7] != b'!<arch>':
			print("No valid Library (AR Format)")
			return
			#sys.exit()

		print("> parsing .lib: ", arg)

		#skip '!<arch> ' header from beginning
		off_start = 8

		cnt = 0
		limit = 5


		while (len(dat) > off_start + 60 and cnt < limit):


			current_file = self.parseElem(dat, off_start)

			self.files.append(current_file)


			file_size = current_file['file_size']
			file_data_start = current_file['file_data_start']

			#calcuclate next meta data offset
			off_start = file_data_start + file_size

			#"Each data section is 2 byte aligned. If it would end on an odd offset, a newline ('\n', 0x0A) is used as filler."
			if (off_start % 2 != 0):
				off_start += 1

			#cnt+=1

		print("> Done parsing .lib\n")



	#Handle special "//              " library member which stores oversized file_identifiers.
	#File identifiers with patter "/12345          " give the index to the huge '00' separated string 
	# which stores the oversized file_identifiers (here: e.g. filesystem paths)
	def parseSpecialIdx(self, in_bytes):

		found_entries = {}
		str_builder = ""
		for i in range(len(in_bytes)):
			if(in_bytes[i] == 0):
				found_entries[i - len(str_builder)] = str_builder
				str_builder = ""
			else:
				str_builder += chr(in_bytes[i])

		self.names = found_entries

		print("2. Found %d oversized filenames" % len(self.names))


	#Handle special "/               " library member which stores offsets to library file members and
	#their corresponding function exports (== public symbols) (e.g. at 0xdeedbeef:__imp__sprintf())
	def parseSpecial(self, in_bytes):

		offsets = []
		found_entries = []

		#first 4 bytes = amount of entries / offsets / functions in the library
		public_symbols = int.from_bytes(in_bytes[:4], 'big')

		print("1. Found: %s public_symbols" % public_symbols)

		in_bytes = in_bytes[4:]

		for i in range(public_symbols):
			offsets.append(in_bytes[4*i:4*i+4])

		in_bytes = in_bytes[4*i+4:]

		str_builder = ""
		for j in range(len(in_bytes)):
			if(in_bytes[j] == 0):
				found_entries.append(str_builder)
				str_builder = ""
			else:
				str_builder += chr(in_bytes[j])


		#self.public_offsets = offsets
		#self.public_names = found_entries

		for k in range(len(offsets)):
			#print("0x%x: %s" % (int.from_bytes(offsets[k], 'big'), found_entries[k]))
			#self.publics[int.from_bytes(offsets[k], 'big')] = found_entries[k]
			self.publics[found_entries[k]] = int.from_bytes(offsets[k], 'big')


	#Print a hexDump of a byte segment / helper function
	def printHexDump(self, off_start, off_end, data, width):
		in_bytes = data[off_start:off_end]
		str_builder = ""
		print("HexDumping %d bytes from 0x%x:" % (len(in_bytes), off_start))
		print("-" * (60))
		for i in range(len(in_bytes)):

			if(i%width == 0 and i>0):
				print(str_builder)
				str_builder = ""

			str_builder += ("0x%-*x " % (3, in_bytes[i]))

		print(str_builder)	
		print("-" * (60))
		print("")

	"""
	def printFileHeader(self):
		print("")
		print("-" * (60))
		print("File: %s" % self.file_identifier)
		print("File Header Begin: 0x%x" % self.file_header_start)
		print("Modified: %d" % self.file_mod_timestamp)
		print("Owner ID: %d" % self.file_owner_id)
		print("Group ID: %d" % self.file_group_id)
		print("File Mode: %d" % self.file_mode)
		print("File Data Begin: 0x%x" % self.file_data_start)
		print("File Size: %d" % self.file_size)
		if (self.file_eof[0] == 96 and self.file_eof[1] == 10):
			print("EOF match: 0x%x 0x0%x" % ( int(self.file_eof[0]), int(self.file_eof[1])))
		else:
			print("ERROR: EOF Signature missmatch, something went wrong while parsing lib")
			sys.exit()
		print("-" * (60))
		print("")
	"""

	#Build ASCII decimals from byte segment
	def decFromBytes(self, in_bytes):
		dec = 0
		for byte in in_bytes:
			if (byte <= 57 and byte >= 48):
				dec = dec * 10 + (byte-48)

		return dec

