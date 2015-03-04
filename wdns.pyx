"""
Low-level DNS library.  Python bindings.

domain = 'fsi.io'
name = str_to_name(domain) -> b'\\x03fsi\\x02io\\x00'
domain_to_str(name) -> 'fsi.io.'

rname = reverse_name(name) -> b'\\x02io\\x03fsi\\x00'
left_chop(name) -> b'\\x02io\\x00'
count_labels(name) -> 2

is_subdomain(str_to_name('www.' + domain), name) -> True
is_subdomain(name, str_to_name('www.' + domain)) -> False

str_to_rrtype('A') -> 1
opcode_to_str(0) -> 'QUERY'
rcode_to_str(3) -> 'NXDOMAIN'

rrclass_to_str(1) -> 'IN'
rrtype_to_str(16) -> 'TXT'
rdata_to_str(b'\\x10text record data', wdns.TYPE_TXT, wdns.CLASS_IN) ->
        '"text record data"'
"""

include "wdns.pxi"

from wdns_constants import *

class MessageParseException(Exception):
    """
    Raised when message_parse is called with invalid data.
    """

class NameException(Exception):
    """
    Raised when an invalid name is passed to a function.
    """

class RdataReprException(Exception):
    """
    Raised when binary record data can not be successfully converted to
    presentation format.  Can occur if the data itself is corrupt or if the
    rrtype or rrclass fields are incorrect for the binary data.
    """

def len_name(bytes py_name):
    """
    len_name(name) -> len(name)

    @param name: A wire format DNS name
    @type name: string

    @return: length of the wire format name
    @rtype: int

    @raise NameException: If name is malformed.
    """
    cdef wdns_res res
    cdef uint8_t *name
    cdef uint8_t *name_end
    cdef size_t sz

    name = py_name
    name_end = name + len(py_name)
    res = wdns_len_uname(name, name_end, &sz)
    if res != wdns_res_success:
        raise NameException, repr(py_name)
    return sz

def reverse_name(bytes py_name):
    """
    reverse(name)

    reverses the fields of name

    e.g. '\\x03fsi\\x02io\\x00' -> '\\x02io\\x03fsi\\x00'

    @param name: A wire format DNS name
    @type name: string

    @rtype: string, A wire format DNS name
    @return: name, fields reversed

    @raise NameException: If name is malformed.
    """
    cdef uint8_t *name
    cdef wdns_res res
    cdef uint8_t rev[WDNS_MAXLEN_NAME]

    sz = len_name(py_name)
    if sz > WDNS_MAXLEN_NAME:
        raise NameException, repr(py_name)
    name = py_name
    res = wdns_reverse_name(name, sz, rev)
    if res != wdns_res_success:
        raise NameException, repr(name)
    return name[:sz]

def left_chop(bytes py_name):
    """
    left_chop(name)

    @param name: A wire format DNS name
    @type name: string

    @return: name with the leftmost label removed
    @rtype: string, A wire format DNS name

    @raise NameException: If name is malformed.
    """
    cdef wdns_name_t chop
    cdef wdns_name_t name
    cdef wdns_res res
    cdef size_t sz

    name.data = py_name
    name.len = len(py_name)

    res = wdns_len_uname(name.data, name.data + name.len, &sz)
    if res != wdns_res_success:
        raise NameException, repr(py_name)

    res = wdns_left_chop(&name, &chop)
    if res != wdns_res_success:
        raise NameException, repr(py_name)
    return chop.data[:chop.len]

def count_labels(bytes py_name):
    """
    count_labels(name)

    Returns the number of labels in a wire format DNS name.

    @param name: A wire format DNS name
    @type name: string

    @rtype: int
    """
    cdef wdns_name_t name
    cdef wdns_res res
    cdef size_t nlabels
    cdef size_t sz

    name.data = py_name
    name.len = len(py_name)

    res = wdns_len_uname(name.data, name.data + name.len, &sz)
    if res != wdns_res_success:
        raise NameException, repr(py_name)

    res = wdns_count_labels(&name, &nlabels)
    if res != wdns_res_success:
        raise NameException, repr(py_name)
    return nlabels

def is_subdomain(bytes py_name0, bytes py_name1):
    """
    is_subdomain(a, b)

    Returns whether or not b is a subdomain of a.

    @param a: A wire format DNS name
    @type a: string
    @param b: A wire format DNS name
    @type b: string

    @rtype: bool
    """
    cdef bool val
    cdef wdns_name_t name0
    cdef wdns_name_t name1
    cdef size_t sz

    name0.data = py_name0
    name0.len = len(py_name0)

    name1.data = py_name1
    name1.len = len(py_name1)

    res = wdns_len_uname(name0.data, name0.data + name0.len, &sz)
    if res != wdns_res_success:
        raise NameException, repr(py_name0)

    res = wdns_len_uname(name1.data, name1.data + name1.len, &sz)
    if res != wdns_res_success:
        raise NameException, repr(py_name1)

    res = wdns_is_subdomain(&name0, &name1, &val)
    if res != wdns_res_success:
        raise NameException
    return val

def domain_to_str(bytes src):
    """
    domain_to_str(src)

    Decodes a wire format domain name.

    @param src: A wire format DNS name
    @type src: bytes

    @return: Decoded domain name.
    @rtype: string
    """
    cdef char dst[WDNS_PRESLEN_NAME]
    cdef size_t sz

    if len(src) > WDNS_MAXLEN_NAME:
        raise NameException, repr(src)

    sz = wdns_domain_to_str(src, len(src), dst)
    if sz != len(src):
        raise NameException, repr(src)

    s = dst
    if isinstance(s, str):
        # Python 2: 's' is already type 'str', and calling .decode()
        # would return type 'unicode'. Instead return 's' directly.
        return s
    else:
        # Python 3: 's' is a 'bytes' object, and calling .decode()
        # will return type 'str'.
        return s.decode('ascii')

def str_to_rrtype(str src):
    """
    str_to_rrtype(src)

    Returns the numeric rrtype for src.
    e.g. A -> 1, NS -> 2

    @type src: string

    @rtype: int

    @raise Exception: Invalid or unknown rtype string.
    """
    cdef uint16_t res
    res = wdns_str_to_rrtype(src.encode('ascii'))
    if res == 0:
        raise Exception, 'wdns_str_to_rrtype() failed'
    return res

def str_to_name(src):
    """
    str_to_name(src)

    Encodes a wire format domain name.

    @type src: string

    @return: Wire-format domain name.
    @rtype: string

    @except Exception: Name longer than WDNS_MAXLEN_NAME or memory
    allocation error.
    """
    cdef wdns_name_t name
    cdef wdns_res res

    if isinstance(src, bytes):
        # Python 2 or 3: 'src' can be directly passed to libwdns.
        res = wdns_str_to_name(src, &name)
    else:
        # Python 3: bytes != str, so 'src' must be converted first.
        res = wdns_str_to_name(src.encode('ascii'), &name)
    if res != wdns_res_success:
        raise Exception, 'wdns_str_to_name() failed'
    try:
        s = name.data[:name.len]
    finally:
        free(name.data)
    return s

def opcode_to_str(uint16_t dns_opcode):
    """
    opcode_to_str(dns_opcode)

    Converts a DNS opcode to string presentation format.

    @type dns_opcode: int

    @rtype: string
    """
    cdef char *s
    s = wdns_opcode_to_str(dns_opcode)
    if s == NULL:
        return str(dns_opcode)
    return str(s.decode('ascii'))

def rcode_to_str(uint16_t dns_rcode):
    """
    rcode_to_str(dns_rcode)

    Converts a DNS rcode to string presentation format.

    @type dns_rcode: int

    @rtype: string
    """
    cdef char *s
    s = wdns_rcode_to_str(dns_rcode)
    if s == NULL:
        return str(dns_rcode)
    return str(s.decode('ascii'))

def rrclass_to_str(uint16_t dns_class):
    """
    rrclass_to_str(dns_class)

    Converts a DNS rrclass to string presentation format.

    @type dns_class: int

    @rtype: string
    """
    cdef char *s
    s = wdns_rrclass_to_str(dns_class)
    if s == NULL:
        return str(dns_class)
    return str(s.decode('ascii'))

def rrtype_to_str(uint16_t dns_type):
    """
    rrtype_to_str(dns_type)

    Converts a DNS rrtype to string presentation format.

    @type dns_type: int

    @rtype: string
    """
    cdef char *s
    s = wdns_rrtype_to_str(dns_type)
    if s == NULL:
        return 'TYPE' + str(dns_type)
    return str(s.decode('ascii'))

def rdata_to_str(bytes rdata, uint16_t rrtype, uint16_t rrclass):
    """
    rdata_to_str(data, rrtype, rrclass)

    Converts a DNS rdata record to string presentation format.  Requires
    rrtype and rrclass.

    @type rdata: string (binary)
    @type rrtype: int
    @type rrclass: int

    @rtype: string
    """
    cdef char *dst
    cdef wdns_res res

    if rdata == None:
        raise Exception, 'rdata object not initialized'

    dst = wdns_rdata_to_str(rdata, len(rdata), rrtype, rrclass)
    if dst == NULL:
        raise RdataReprException

    try:
        s = str((<bytes> dst).decode('ascii'))
    finally:
        free(dst)
    return s

def parse_message(bytes pkt):
    """
    parse_message(pkt)

    Parses a DNS message from a payload.

    @type pkt: binary payload data

    @rtype: wdns.message

    @raise MessageParseException: If the message is invalid.
    """
    cdef wdns_message_t m
    cdef wdns_rdata_t *dns_rdata
    cdef wdns_rrset_t *dns_rrset
    cdef wdns_rrset_array_t *a
    cdef wdns_res res

    res = wdns_parse_message(&m, pkt, len(pkt))
    if res == wdns_res_success:
        msg = message()
        msg.id = m.id
        msg.flags = m.flags
        msg.rcode = m.rcode
        msg.opcode = (m.flags & 0x7800) >> 11

        if (m.flags >> 15) & 0x01:
            msg.qr = True
        if (m.flags >> 10) & 0x01:
            msg.aa = True
        if (m.flags >> 9) & 0x01:
            msg.tc = True
        if (m.flags >> 8) & 0x01:
            msg.rd = True
        if (m.flags >> 7) & 0x01:
            msg.ra = True
        if (m.flags >> 5) & 0x01:
            msg.ad = True
        if (m.flags >> 4) & 0x01:
            msg.cd = True

        for i from 0 <= i < 4:
            a = &m.sections[i]
            for j from 0 <= j < a.n_rrsets:
                dns_rrset = &a.rrsets[j]
                py_rrset = rrset()

                name = dns_rrset[0].name.data[:dns_rrset[0].name.len]
                if i == 0:
                    q = qrr()
                    q.name = name
                    q.rrclass = dns_rrset.rrclass
                    q.rrtype = dns_rrset.rrtype
                    msg.sec[0].append(q)
                else:
                    py_rrset.name = name
                    py_rrset.rrclass = dns_rrset.rrclass
                    py_rrset.rrtype = dns_rrset.rrtype
                    py_rrset.rrttl = dns_rrset.rrttl
                    for k from 0 <= k < dns_rrset.n_rdatas:
                        dns_rdata = dns_rrset[0].rdatas[k]
                        py_rdata = dns_rdata.data[:dns_rdata.len]
                        py_rdata_obj = rdata(py_rdata, dns_rrset.rrclass, dns_rrset.rrtype)
                        py_rrset.rdata.append(py_rdata_obj)
                    msg.sec[i].append(py_rrset)

        wdns_clear_message(&m)
        return msg
    else:
        raise MessageParseException('wdns_parse_message() returned %s' % res)

cdef class message(object):
    """
    An object wrapping a DNS message.
    """
    cdef public int id
    """
    @ivar id: Identifier
    @type id: int
    """
    cdef public int flags
    """
    @ivar flags: Query/Response Flag
    @type flags: int
    """
    cdef public int rcode
    """
    @ivar rcode: Response Code
    @type rcode: int
    """
    cdef public int opcode
    """
    @ivar opcode: Opcode
    @type opcode: int
    """
    cdef public list sec
    """
    @ivar sec: Sections
    @type sec: list
    """

    cdef public bool qr
    """
    @ivar qr: Query/Response Flag
    @type qr: bool
    """
    cdef public bool aa
    """
    @ivar aa: Authoritative Answer Flag
    @type aa: bool
    """
    cdef public bool tc
    """
    @ivar tc: Truncation Flag
    @type tc: bool
    """
    cdef public bool rd
    """
    @ivar rd: Recursion Desired Flag
    @type rd: bool
    """
    cdef public bool ra
    """
    @ivar ra: Recursion Available Flag
    @type ra: bool
    """
    cdef public bool ad
    """
    @ivar ad: Authenticated Data Flag
    @type ad: bool
    """
    cdef public bool cd
    """
    @ivar cd: Checking Disabled Flag
    @type cd: bool
    """

    parse = staticmethod(parse_message)

    def __init__(self):
        self.sec = [ [], [], [], [] ]

    def repr_flags(self):
        f = []
        if self.qr:
            f.append('qr')
        if self.aa:
            f.append('aa')
        if self.tc:
            f.append('tc')
        if self.rd:
            f.append('rd')
        if self.ra:
            f.append('ra')
        if self.ad:
            f.append('ad')
        if self.cd:
            f.append('cd')
        return ' '.join(f)

    def __repr__(self):
        s = ';; ->>HEADER<<- opcode: %s, rcode: %s, id: %s\n' % (
            opcode_to_str(self.opcode),
            rcode_to_str(self.rcode),
            self.id
        )
        s += ';; flags: %s; QUERY: %s, ANSWER: %s, AUTHORITY: %s, ADDITIONAL: %s\n''' % (
            self.repr_flags(),
            len(self.sec[0]),
            len(self.sec[1]),
            len(self.sec[2]),
            len(self.sec[3])
        )

        s += '\n;; QUESTION SECTION:\n'
        for dns_rrset in self.sec[0]:
            s += ';%s\n' % dns_rrset

        s += '\n;; ANSWER SECTION:\n'
        for dns_rrset in self.sec[1]:
            s += '%s\n' % dns_rrset

        s += '\n;; AUTHORITY SECTION:\n'
        for dns_rrset in self.sec[2]:
            s += '%s\n' % dns_rrset

        s += '\n;; ADDITIONAL SECTION:\n'
        for dns_rrset in self.sec[3]:
            s += '%s\n' % dns_rrset

        return s

cdef class qrr(object):
    """
    Query Resource Record
    """
    cdef public bytes name
    """
    @ivar name: Question Name
    @type name: string
    """
    cdef public int rrclass
    """
    @ivar rrclass: Question Class
    @type rrclass: int
    """
    cdef public int rrtype
    """
    @ivar rrtype: Question Type
    @type rrtype: int
    """

    def __repr__(self):
        return '%s %s %s' % (
            domain_to_str(self.name),
            rrclass_to_str(self.rrclass),
            rrtype_to_str(self.rrtype),
        )

cdef class rrset(object):
    """
    Resource Record Set
    """
    cdef public bytes name
    """
    @ivar name: Name
    @type name: string
    """
    cdef public int rrclass
    """
    @ivar rrclass: Class
    @type rrclass: int
    """
    cdef public int rrtype
    """
    @ivar rrtype: Type
    @type rrtype: int
    """
    cdef public unsigned int rrttl
    """
    @ivar rrttl: TTL
    @type rrttl: int
    """
    cdef public list rdata
    """
    @ivar rdata: List of binary resource data
    @type rdata: list
    """

    def __init__(self):
        self.rdata = []

    def __repr__(self):
        rr = []
        for rd in self.rdata:
            rr.append('%s %s %s %s %s' % (
                domain_to_str(self.name),
                self.rrttl,
                rrclass_to_str(self.rrclass),
                rrtype_to_str(self.rrtype),
                rd
            ))
        return '\n'.join(rr)

cdef class rdata(object):
    """
    Resource Data
    """
    cdef public bytes data
    """
    @ivar data: Binary data
    @type data: binary string
    """
    cdef public int rrclass
    """
    @ivar rrclass: Class
    @type rrclass: int
    """
    cdef public int rrtype
    """
    @ivar rrtype: Type
    @type rrtype: int
    """

    def __init__(self, bytes data, int rrclass, int rrtype):
        """
        __init__(self, data, rrclass, rrtype)
        """
        self.data = data
        self.rrclass = rrclass
        self.rrtype = rrtype

    def __repr__(self):
        return rdata_to_str(self.data, self.rrtype, self.rrclass)

