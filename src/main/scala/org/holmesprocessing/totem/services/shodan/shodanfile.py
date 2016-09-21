import shodan

from tornado.web import HTTPError


def runShodan(api, input):

    # Wrap the request in a try/ except block to catch errors
    try:
        # Lookup the host
        return {
            "host": api.host(input),
                }

    except shodan.APIError as e:
        print('Error: {}'.format(e))
        raise HTTPError(401, "API Error: {}".format(e), reason="API Error")
