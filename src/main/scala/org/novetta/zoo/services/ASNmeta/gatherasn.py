import dns
import dns.name
import dns.query
import dns.resolver
import ipaddress

class IPFormatError(Exception):
    pass


class IPTypeError(Exception):
    pass


class GatherASN:
    def _reverse_address(self):
        if self.ip.version == 4:
            reverseip = str(self.ip).split('.')[::-1]
        else:
            reverseip = self.ip.exploded[::-1].replace(':', '')
        return '.'.join(reverseip) 


    def _parse_results(self, data):
        return [out.strip() for out in data.rrset[0].strings[0].split('|')]


    def _perform_query(self, domain, rdtype):
        """
        Performs a DNS (UDP) query with flags and configurations parameters.

        Args: 
            domain (str): sdomain i.e. google.com
            nnserver (str): nameserver to query
            rtype (str or int): rtype to query http://en.wikipedia.org/wiki/List_of_DNS_record_types
            timeout (int): time to wait before timeout        

        """
        domain = dns.name.from_text(domain)

        try:
            result = self.resolver.query(domain, rdtype=rdtype)
        except dns.resolver.NoAnswer:
            print("%s : The response did not contain a answer for %s." % (rdtype, domain))
        except dns.resolver.NXDOMAIN:
            print("%s : The query name does not exist for %s." % (rdtype, domain))
        except dns.resolver.Timeout:
            print("%s : The query could not be found in the specified lifetime for %s." % (rdtype, domain))
        except dns.resolver.NoNameservers:
            print("%s : No non-broken nameservers are available to answer the question using nameserver %s" % (rdtype, domain))
        else:
            print("%s : Queried %s successfully!" % (rdtype, domain))
            return result
        return None


    def query_asn_name(self, asn):
        parsed_ip = "{0}.{1}".format(asn, self.servername) 

        query_result = self._perform_query(parsed_ip, 'TXT')

        if query_result is not None:
            temp = self._parse_results(query_result)
            #self.data['asn_number']     = temp[0]
            #self.data['cc']             = temp[1]
            #self.data['registry']       = temp[2]
            self.data['data_allocated'] = temp[3]
            self.data['asn_name']       = temp[4]
            print(temp)


    def query_asn_origin(self):
        if self.ip.version == 4:
            parsed_ip = "{0}.{1}".format(self.reversed_ip, self.serverv4) 
        elif self.ip.version == 6:
            parsed_ip = "{0}.{1}".format(self.reversed_ip, self.serverv6) 

        query_result = self._perform_query(parsed_ip, 'TXT')

        if query_result is not None:
            temp = self._parse_results(query_result)
            self.data['asn_number'] = temp[0]
            self.data['bgp_prefix'] = temp[1]
            self.data['cc']         = temp[2]
            self.data['registry']   = temp[3]
            self.data['data_allocated'] = temp[4]
            print(temp)


    def query_asn_peer(self):        
        parsed_ip = "{0}.{1}".format(self.reversed_ip, self.serverpeer) 

        query_result = self._perform_query(parsed_ip, 'TXT')

        if query_result is not None:
            temp = self._parse_results(query_result)
            self.data['asn_peers']  = temp[0].split(' ')
            print(temp)


    def get_asn_name(self):
        return self.data.get('asn_name', None)


    def get_asn_number(self):
        return self.data.get('asn_number', None)


    def get_asn_peers(self):
        return self.data.get('asn_peers', None)


    def get_bgp_prefix(self):
        return self.data.get('bgp_prefix', None)


    def get_cc(self):
        return self.data.get('cc', None)


    def get_registry(self):
        return self.data.get('registry', None)


    def get_date_allocated(self):
        return self.data.get('data_allocated', None)


    def get_all_known_data(self):
        return self.data


    def get_ip(self):
        return str(self.ip)


    def get_ip_version(self):
        return self.ip.version

    
    def __init__(self, ip, nsserver, serverv4, serverv6, serverpeer, servername, timeout=10):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [nsserver]
        self.resolver.timeout = timeout
        self.resolver.lifetime = 50
        self.serverv4 = serverv4
        self.serverv6 = serverv6
        self.serverpeer = serverpeer
        self.servername = servername

        self.data = {}
        try:
            self.ip = ipaddress.ip_address(ip)

            # test to make sure the address is publicly accessible
            ###
            # TODO: upgrade to is_global when python 3.5+ is more stable
            ###
            if self.ip.is_private:
                raise IPTypeError()
            self.reversed_ip = self._reverse_address()
        except ValueError:
            raise IPFormatError()
