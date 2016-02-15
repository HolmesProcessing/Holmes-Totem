import configparser
import sys
import requests
import yara

ERROR_CODE = 1

def DownloadFile(url, rulefile):
    r = requests.get(url, stream=True)
    with open(rulefile, 'wb') as f:
        for chunk in r.iter_content(chunk_size=(100*1024)):
            if chunk:
                f.write(chunk)


def main():
    """ Main logic for program """
    cfg = configparser.ConfigParser()
    cfg.read('service.conf')
    rule_location = 'rules.yar'
    get_remote    = False

    # Parse configuration options
    if cfg.has_section('Rules'):
        rule_location = cfg['Rules'].get('local_path', fallback='rules.yar')
        get_remote    = cfg['Rules'].getboolean('get_remote', fallback=False)
        if get_remote:
            DownloadFile(cfg['Rules'].get('download_url'), rule_location)
    else:
        print("Configuration Error: Cannot find Rules section. Using default values.")

    # attempt to compile rules
    try:
        rules = yara.compile(rule_location)
        rules.save(rule_location)
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
