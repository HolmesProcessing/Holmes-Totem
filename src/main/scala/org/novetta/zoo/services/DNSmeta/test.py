import gatherdns
import sys
import pprint

dnsinfo = gatherdns.GatherDNS('8.8.8.8')

auth = dnsinfo.find_authoritative_nameserver(sys.argv[1])
print('authority {}'.format(auth))


rdtypes = ['A', 'AAAA', 'NS', 'MX', 'SOA', 'CNAME', 'TXT', 'PTR']
dnsinfo.query_domain(sys.argv[1], rdtypes)

data = {}
for rdtype in rdtypes:
    function = getattr(dnsinfo, 'get_{}_record'.format(rdtype))
    result = function()
    if result is not None:
        data[rdtype] = result

pprint.pprint(data)
