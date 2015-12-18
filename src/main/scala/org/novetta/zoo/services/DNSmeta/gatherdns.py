import dns
import dns.name
import dns.query
import dns.resolver

class DomainError(Exception):
    pass

class GatherDNS:
    """Helper class for gathering DNS data"""

    def _convert_utf8(self, s):
        """ Decodes string"""
        codecs = ['utf8', 'utf16', 'utf32', 'latin1', 'cp1252', 'ascii']
        
        print(s)

        for i in codecs:
            try:
                return s.decode(i).encode('utf8')
            except:
                pass

        s = "Cannot decode to UTF-8"

        return s


    def _convert_rdclass_to_txt(self, rdclass):
        """ Converts rdclass to human readable form"""
        return {
            1: 'IN',  # the Internet
            2: 'CS',  # the CSNET class (Obsolete - used on for examples in obsolete RFCs)
            3: 'CH',  # a CHAOS class
            4: 'HS'   # Hesiod [Dyer 87]
        }[rdclass]


    def _convert_rdtype_to_txt(self, rdtype):
        """ 
        Converts rdtype to human readable form
        Design pattern was there, so I ran with it. I pulled the additional resource records, which includes experimental and obsolete entries from wikipedia.
        http://en.wikipedia.org/wiki/List_of_DNS_record_types 
        -jg
        """
        return {
            1: 'A',             # a host address
            2: 'NS',            # an authoritative name server
            3: 'MD',            # a mail destination (Obsolete - use MX)
            4: 'MF',            # a mail forwarder (Obsolete - use MX)
            5: 'CNAME',         # the cononical name for an alias
            6: 'SOA',           # marks the start of a zone of authority
            7: 'MB',            # a mailbox domain name (EXPERIMENTAL)
            8: 'MG',            # a mail group member (EXPERIMENTAL)
            9: 'MR',            # a mail rename domain name (EXPERIMENTAL)
            10: 'NULL',         # a null RR (EXPERIMENTAL)
            11: 'WKS',          # a well known service description
            12: 'PTR',          # a domain name pointer
            13: 'HINFO',        # host information
            14: 'MINFO',        # mailbox or mail list information
            15: 'MX',           # mail exchange
            16: 'TXT',          # text strings
            17: 'RP',           # responsible person
            18: 'AFSDB',        # AFS database record
            24: 'SIG',          # signature
            25: 'KEY',          # key record
            28: 'AAAA',         # IPv6 address record
            29: 'LOC',          # location record
            33: 'SRV',          # service locator
            35: 'NAPTR',        # naming authority pointer
            36: 'KX',           # key exchange record
            37: 'CERT',         # certificate record
            39: 'DNAME',        # delegation name
            42: 'APL',          # address prefix list
            43: 'DS',           # delegation signer
            44: 'SSHFP',        # ssh public key fingerprint
            45: 'IPSECKEY',     # ipsec key
            46: 'RRSIG',        # dnssec signature
            47: 'NSEC',         # next-secure record
            48: 'DNSKEY',       # dns key record
            49: 'DHCID',        # dhcp identifier
            50: 'NSEC3',        # nsec record version 3
            51: 'NSEC3PARAM',   # nsec3 parameters
            52: 'TLSA',         # tlsa certificate association
            55: 'HIP',          # host identity protocol
            59: 'CDS',          # child ds
            60: 'CDNSKEY',      # child dnskey
            249: 'TKEY',        # secret key record
            250: 'TSIG',        # transaction signature
            257: 'CAA',         # certification authority authorization
            32768: 'TA',        # dnssec trust authorities
            32769: 'DLV'        # dnssec lookaside validation record
        }[rdtype]


    def _perform_query(self, domain, rdtype):
        """
        Performs a DNS (UDP) query with flags and configurations parameters.

        Args: 
            domain: domain object
            nnserver (str): nameserver to query
            rtype (str or int): rtype to query http://en.wikipedia.org/wiki/List_of_DNS_record_types
            timeout (int): time to wait before timeout        

        """
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


    def _rr_header(self, rdtype):
        return {
            'name':     self.data[rdtype].canonical_name.to_text(),
            'type':     self._convert_rdtype_to_txt(self.data[rdtype].rdtype),
            'class':    self._convert_rdclass_to_txt(self.data[rdtype].rdclass),
            'ttl':      self.data[rdtype].ttl
        }

    def _standard_in_parse(self, rdtype):
        if rdtype in self.data:
            result = self._rr_header(rdtype)
            records = [{'address': rdata.address} 
                        for rdata in self.data[rdtype]]
            result['rdata'] = records
            return result


    def _standard_any_parse(self, rdtype):
        if rdtype in self.data:
            result = self._rr_header(rdtype)
            records = [{'target': rdata.target.to_text()} 
                        for rdata in self.data[rdtype].rrset]
            result['rdata'] = records
            return result


    def get_A_record(self):
        return self._standard_in_parse('A')


    def get_AAAA_record(self):
        return self._standard_in_parse('AAAA')


    def get_CNAME_record(self):
        return self._standard_any_parse('CNAME')


    def get_MX_record(self):
        rdtype = 'MX'
        if rdtype in self.data:
            result = self._rr_header(rdtype)
            records = [{'preference': rdata.preference, 
                        'exchange': rdata.exchange.to_text()} 
                        for rdata in self.data[rdtype]]
            result['rdata'] = records
            return result


    def get_NS_record(self):
        return self._standard_any_parse('NS')


    def get_PTR_record(self):
        return self._standard_any_parse('PTR')


    def get_SOA_record(self):
        rdtype = 'SOA'
        if rdtype in self.data:
            result = self._rr_header(rdtype)
            records = [{'expire':   rdata.expire,
                        'minimum':  rdata.minimum,
                        'mname':    rdata.mname.to_text(),
                        'refresh':  rdata.refresh,
                        'retry':    rdata.retry,
                        'rname':    rdata.rname.to_text(),
                        'serial':   rdata.serial}
                        for rdata in self.data[rdtype]]
            result['rdata'] = records
            return result


    def get_TXT_record(self):
        rdtype = 'TXT'
        if rdtype in self.data:
            result = self._rr_header(rdtype)

# doesn't appear to be needed in python3...I am skeptical
#            records = [{'strings':  self._convert_utf8(rdata.to_text())} 
#                        for rdata in self.data[rdtype]]
            records = [{'strings': rdata.to_text().strip()} 
                        for rdata in self.data[rdtype]]

            result['rdata'] = records
            return result


    def find_authoritative_nameserver(self, domain):
        """
        Attempt to identify the authoritative nameservers. returns a list of 
        authoritative name servers and an IP address...or just an IP address   
        """
        depth = 2
        domain = dns.name.from_text(domain)
        default = dns.resolver.get_default_resolver()
        nsserver = self.resolver.nameservers[0]

        last = False
        while not last:
            sdomain = domain.split(depth)
            last = sdomain[0].to_unicode() == u'@'
            sub = sdomain[1]

            query = dns.message.make_query(sub, dns.rdatatype.NS)
            response = dns.query.udp(query, nsserver)

            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                return False

            rrset = None
            if len(response.authority) > 0:
                rrset = response.authority[0]
            else:
                rrset = response.answer[0]

            rr = rrset[0]
            if rr.rdtype == dns.rdatatype.SOA:
                return(sub.to_text(), nsserver)
            else:
                nsserver = default.query(rr.target).rrset[0].to_text()
                if last:
                    self.resolver.nameservers = [nsserver]
                    return(rr.target.to_text(), nsserver)

            depth += 1

        return False


    def query_domain(self, rdtypes):
        # gather the desired rdtypes
        self.data = {rdtype: self._perform_query(self.domain, rdtype) for rdtype in rdtypes}
        
        # remove none values
        self.data = dict((k,v) for k,v in self.data.items() if v is not None)


    def __init__(self, domain, nsserver, timeout=10):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [nsserver]
        self.resolver.timeout = timeout
        self.resolver.lifetime = 50
        self.data = {}

        try:
            print(domain)
            self.domain = dns.name.from_text(domain)
        except:
            raise DomainError()

