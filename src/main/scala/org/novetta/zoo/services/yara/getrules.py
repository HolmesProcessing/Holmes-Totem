import configparser
import shutil
import sys
import requests

ERROR_CODE = 1

def DownloadFile(url):
	r = requests.get(url, stream=True)
	with open('rules.yar', 'wb') as f:
		for chunk in r.iter_content(chunk_size=(100*1024)):
			if chunk:
				f.write(chunk)
	return 'rules.yar'


def main():
	""" Main logic for program """
	cfg = configparser.ConfigParser()
	cfg.read('service.conf')
	get_remote = False
	rule_location = 'rules.yar'

	# Parse configuration options
	if cfg.has_section('Rules'):
		get_remote = cfg['Rules'].getboolean('get_remote', fallback=False)
		if get_remote:
			rule_location = DownloadFile(cfg['Rules'].get('download_url'))
		else:
			rule_location = cfg['Rules'].get('local_path', fallback='rules.yar')
	else:
		print("Configuration Error: Cannot find Rules section. Using default values.")

	# attempt to compile rules
	try:
		rules = yara.compile(rules_location)
		rules.save('rules.yar')
	except YaraSyntaxError:
		print("Syntax error in the YARA rules.")
		sys.exit(ERROR_CODE)
	except YaraError:
		print("Unknown YARA error.")
		sys.exit(ERROR_CODE)
	except Exception as e:
		print(e)
		sys.exit(ERROR_CODE)

	return 0


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(ERROR_CODE)
