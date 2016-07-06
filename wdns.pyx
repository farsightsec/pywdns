"""
Low-level DNS library.  Python bindings.

domain = 'fsi.io'
name = str_to_name(domain) -> '\\x03fsi\\x02io\\x00'
domain_to_str(name) -> 'fsi.io.'

rname = reverse_name(name) -> '\\x02io\\x03fsi\\x00'
left_chop(name) -> '\\x02io\\x00'
count_labels(name) -> 2

is_subdomain(str_to_name('www.%s' % domain), name) -> True
is_subdomain(name, str_to_name('www.%s' % domain)) -> False

str_to_rrtype('A') -> 1
opcode_to_str(0) -> 'QUERY'
rcode_to_str(3) -> 'NXDOMAIN'

rrclass_to_str(1) -> 'IN'
rrtype_to_str(16) -> 'TXT'
rdata_to_str('\\x10text record data', wdns.TYPE_TXT, wdns.CLASS_IN) ->
        'text record data'
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

def len_name(str py_name):
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

    name = <uint8_t *> PyString_AsString(py_name)
    name_end = name + len(py_name)
    res = wdns_len_uname(name, name_end, &sz)
    if res != wdns_res_success:
        raise NameException, repr(py_name)
    return sz

def reverse_name(str name):
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
    cdef wdns_res res
    cdef uint8_t rev[WDNS_MAXLEN_NAME]

    sz = len_name(name)
    if sz > WDNS_MAXLEN_NAME:
        raise NameException, repr(name)
    res = wdns_reverse_name(<uint8_t *> PyString_AsString(name), sz, rev)
    if res != wdns_res_success:
        raise NameException, repr(name)
    return PyString_FromStringAndSize(<char *> rev, sz)

def left_chop(str py_name):
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

    name.data = <uint8_t *> PyString_AsString(py_name)
    name.len = len(py_name)

    res = wdns_len_uname(name.data, name.data + name.len, &sz)
    if res != wdns_res_success:
        raise NameException, repr(py_name)

    res = wdns_left_chop(&name, &chop)
    if res != wdns_res_success:
        raise NameException, repr(py_name)
    return PyString_FromStringAndSize(<char *> chop.data, chop.len)

def count_labels(str py_name):
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

    name.data = <uint8_t *> PyString_AsString(py_name)
    name.len = len(py_name)

    res = wdns_len_uname(name.data, name.data + name.len, &sz)
    if res != wdns_res_success:
        raise NameException, repr(py_name)

    res = wdns_count_labels(&name, &nlabels)
    if res != wdns_res_success:
        raise NameException, repr(py_name)
    return nlabels

def is_subdomain(str py_name0, str py_name1):
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

    name0.data = <uint8_t *> PyString_AsString(py_name0)
    name0.len = len(py_name0)

    name1.data = <uint8_t *> PyString_AsString(py_name1)
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

def domain_to_str(str src):
    """
    domain_to_str(src)

    Decodes a wire format domain name.

    @param src: A wire format DNS name
    @type src: string

    @return: Decoded domain name.
    @rtype: string
    """
    cdef char dst[WDNS_PRESLEN_NAME]
    cdef size_t sz

    if len(src) > WDNS_MAXLEN_NAME:
        raise NameException, repr(src)

    sz = wdns_domain_to_str(<uint8_t *> PyString_AsString(src), len(src), dst)
    if sz != len(src):
        raise NameException, repr(src)

    return PyString_FromString(dst)

def str_to_rrtype(char *src):
    """
    str_to_rrtype(src)

    Returns the numeric rrtype for src.
    e.g. A -> 1, NS -> 2

    @type src: string

    @rtype: int

    @raise Exception: Invalid or unknown rtype string.
    """
    cdef uint16_t res
    res = wdns_str_to_rrtype(src)
    if res == 0:
        raise Exception, 'wdns_str_to_rrtype() failed'
    return res

def str_to_rrclass(char *src):
    """
    str_to_rrclass(src)

    Returns the numeric rrclass for src.
    e.g. IN -> 1, CH -> 3

    @type src: string

    @rtype: int

    @raise Exception: Invalid or unknown rtype string.
    """
    cdef uint16_t res
    res = wdns_str_to_rrclass(src)
    if res == 0:
        raise Exception, 'wdns_str_to_rrclass() failed'
    return res

def str_to_rcode(char *src):
    """
    str_to_rcode(src)

    Returns the numeric rcode for src.
    e.g. NOERROR -> 1, NXDOMAIN -> 3

    @type src: string

    @rtype: int

    @raise Exception: Invalid or unknown rtype string.
    """
    cdef uint16_t rval
    cdef wdns_res res
    res = wdns_str_to_rcode(src, &rval)
    if res != wdns_res_success:
        raise Exception, 'wdns_str_to_rcode() failed: %s' % wdns_res_to_str(res)
    return rval

def str_to_rdata(str s, uint16_t rrtype, uint16_t rrclass):
    """
    str_to_rdata(s, rrtype, rrclass)

    Converts a string presentation DNS rdata record to wire format.  Requires
    rrtype and rrclass.

    @type s: string
    @type rrtype: int
    @type rrclass: int

    @rtype: string (binary)
    """

    cdef char *dst
    cdef wdns_res res
    cdef uint8_t *rd
    cdef size_t rdlen

    if s == None:
        raise TypeError, 's may not be None'

    res = wdns_str_to_rdata(PyString_AsString(s), rrtype, rrclass, &rd, &rdlen)
    if res != wdns_res_success:
        raise Exception, 'wdns_str_to_rdata() failed'

    rdata = PyString_FromStringAndSize(<char *>rd, rdlen)
    free(rd)
    return rdata

def str_to_name(char *src):
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

    res = wdns_str_to_name(src, &name)
    if res != wdns_res_success:
        raise Exception, 'wdns_str_to_name() failed'
    s = PyString_FromStringAndSize(<char *> name.data, name.len)
    free(name.data)
    return s

def str_to_name_case(char *src):
    """
    str_to_name_case(src)

    Encodes a wire format domain name, preserving case.

    @type src: string

    @return: Wire-format domain name.
    @rtype: string

    @except Exception: Name longer than WDNS_MAXLEN_NAME or memory
    allocation error.
    """
    cdef wdns_name_t name
    cdef wdns_res res

    res = wdns_str_to_name_case(src, &name)
    if res != wdns_res_success:
        raise Exception, 'wdns_str_to_name() failed'
    s = PyString_FromStringAndSize(<char *> name.data, name.len)
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
    return s

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
    return s

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
    return s

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
    return s

def rdata_to_str(str rdata, uint16_t rrtype, uint16_t rrclass):
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
    cdef uint8_t *rd
    cdef uint16_t rdlen
    cdef wdns_res res

    if rdata == None:
        raise Exception, 'rdata object not initialized'

    rd = <uint8_t *> PyString_AsString(rdata)
    rdlen = PyString_Size(rdata)

    dst = wdns_rdata_to_str(rd, rdlen, rrtype, rrclass)
    if dst == NULL:
        raise RdataReprException

    s = PyString_FromString(dst)
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
    cdef uint8_t *p

    p = <uint8_t *> PyString_AsString(pkt)
    if p == NULL:
        raise Exception('PyString_AsString() failed')

    res = wdns_parse_message(&m, p, PyString_Size(pkt))
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

                name = PyString_FromStringAndSize(<char *> dns_rrset[0].name.data, dns_rrset[0].name.len)
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
                        py_rdata = PyString_FromStringAndSize(<char *> dns_rdata.data, dns_rdata.len)
                        py_rdata_obj = rdata(py_rdata, dns_rrset.rrclass, dns_rrset.rrtype)
                        py_rrset.rdata.append(py_rdata_obj)
                    msg.sec[i].append(py_rrset)

        if m.edns.present:
            opts = None
            if m.edns.options:
                opts = PyString_FromStringAndSize(<char *>m.edns.options.data, m.edns.options.len)
            msg.edns = edns(m.edns.version, m.edns.flags, m.edns.size, opts)
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
    cdef public object edns
    """
    @ivar edns: EDNS information
    @type edns: edns
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
        self.edns = None

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
    cdef public str name
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
    cdef public str name
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
    cdef public str data
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

    def __init__(self, str data, int rrclass, int rrtype):
        """
        __init__(self, data, rrclass, rrtype)
        """
        self.data = data
        self.rrclass = rrclass
        self.rrtype = rrtype

    def __repr__(self):
        return rdata_to_str(self.data, self.rrtype, self.rrclass)

cdef class edns(object):
    """
    """
    cdef public int version
    """
    @ivar version: EDNS version
    @type version: int
    """
    cdef public int flags
    """
    @ivar flags: EDNS Flags
    @type flags: int
    """
    cdef public int size
    """
    @ivar size: Maximum message size
    @type size: int
    """
    cdef public str options
    """
    @ivar options: OPT RR contents
    @type options: str
    """

    def __init__(self, version, flags, size, options):
        self.version = version
        self.flags = flags
        self.size = size
        self.options = options

    def __repr__(self):
        return ";; EDNS{} SIZE: {}, FLAGS: {:x}".format(self.version, self.size, self.flags)
