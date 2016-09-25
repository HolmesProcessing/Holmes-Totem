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
        if e.value == 'No information available for that IP.':
            raise HTTPError(404, "API Error: {}".format(e), reason="API Error")
        else:
            raise HTTPError(401, "API Error: {}".format(e), reason="API Error")
