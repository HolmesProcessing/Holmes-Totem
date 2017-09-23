#richDB v0.4
#Parse a Folder of Microsoft Libraries (.Lib) to build a function db
#by Timo 'T31M' Geissler

import parselib #by kischju.re
import richlib #by T31M

import sys, os, struct, time, pickle
from collections import defaultdict

def parse(path):
	cwd = os.getcwd()
	os.chdir(path)

	libs = [name for name in os.listdir(".") if name.endswith(".Lib") or name.endswith(".lib")]

	obj_store = []
	dupe_check = defaultdict(dict)
	skip = 0

	start = time.perf_counter()

	for lib in libs:

		rl = richlib.richLib()
		rl.parseLib(lib)

		print("> Parsing and Storing obj data from lib")
		for f in rl.files:
			if ("obj" in str(f['file_identifier'])):
				curr_compid = 0

				data = parselib.parse_obj(f['file_data'])
				for elem in data['syms']:
					if (elem['name'] == b'@comp.id'): #should be the first element
						curr_compid = elem['value']
						break
				
				for elem in data['syms']:
					if (elem['scnum'] > 0 and elem['type'] == 32):

						sig = {
							'name': elem['name'],
							'compid': curr_compid,
							'obj_name': str(f['file_identifier']),
							'raw': data['secs'][elem['scnum']-1]['raw'],
							'relocs': data['secs'][elem['scnum']-1]['relocs'],
							'syms': data['syms']
							}

						if dupe_check[data['secs'][elem['scnum']-1]['raw']] != {}:
							if dupe_check[data['secs'][elem['scnum']-1]['raw']] == sig:
								print("duplicate detected")
								skip += 1
								continue

						obj_store.append(sig)

						dupe_check[data['secs'][elem['scnum']-1]['raw']] = sig

	stop = time.perf_counter()

	print("Stored %d objects from lib (%d duplicates skipped)" % (len(obj_store), skip))
	print("Took %f sec" % (stop-start))
	print("Total Size?: %db" % sys.getsizeof(obj_store))
	print("> Done storing data\n")


	compids = {}
	compid_store = {}

	for obj in obj_store:
		if obj['compid'] in compids:
			compids[obj['compid']] += 1
			compid_store[obj['compid']].append(obj)
		else:
			compids[obj['compid']] = 1
			compid_store[obj['compid']] = [obj]

	for cmpid in compids:
		print ("0x%x: %d" % (cmpid, compids[cmpid]))
	print("")

	os.chdir(cwd)

	for cmpid in compid_store:
		with open(str(cmpid) + ".pickle", 'wb') as outfile:
			pickle.dump(compid_store[cmpid], outfile)

if __name__ == "__main__":
	
	if len(sys.argv) < 2:
		print("Usage: {} <VS Library Folder>".format(sys.argv[0]))
		sys.exit(-1)
	for arg in sys.argv[1:]:
		signatureDB = parse(arg)

	