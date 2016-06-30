import gatherasn
import sys
import pprint

ipaddress = sys.argv[1]

dns_server = '8.8.8.8'
asn_ipv4_query = 'origin.asn.cymru.com'
asn_ipv6_query = 'origin6.asn.cymru.com'
asn_peer_query = 'peer.asn.cymru.com'
asn_name_query = 'asn.cymru.com'


asninfo = gatherasn.GatherASN(dns_server, 
	asn_ipv4_query, 
	asn_ipv6_query,
	asn_peer_query,
	asn_name_query)
asninfo.query_asn_origin(ipaddress)
asninfo.query_asn_peer(ipaddress)

name = 'AS{}'.format(asninfo.data['asn_number'])
asninfo.query_asn_name(name)

data = asninfo.get_all_known_data()


pprint.pprint(data)
