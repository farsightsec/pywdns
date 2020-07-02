#!/usr/bin/env python
# Copyright (c) 2009-2014 by Farsight Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from wdns import (
    CLASS_IN,
    count_labels,
    domain_to_str,
    is_subdomain,
    left_chop,
    len_name,
    opcode_to_str,
    parse_message,
    rcode_to_str,
    rdata_to_str,
    reverse_name,
    rrclass_to_str,
    rrtype_to_str,
    str_to_name,
    str_to_name_case,
    str_to_rcode,
    str_to_rdata,
    str_to_rrclass,
    str_to_rrtype,
    TYPE_TXT,
)


class TestWDNS(unittest.TestCase):

    def test_domain_manipulation(self):
        domain = 'fsi.io'
        name = str_to_name(domain)
        assert name == b'\x03fsi\x02io\x00', name
        assert domain_to_str(name) == 'fsi.io.', domain_to_str(name)
        rname = reverse_name(name)
        assert rname == b'\x02io\x03fsi\x00', rname
        assert left_chop(name) == b'\x02io\x00', left_chop(name)
        assert count_labels(name) == 2, count_labels(name)
        assert is_subdomain(str_to_name('www.' + domain), name) is True
        assert is_subdomain(name, str_to_name('www.' + domain)) is False

    def test_opcode_conversions(self):
        assert str_to_rrtype('A') == 1, str_to_rrtype('A')
        assert rrtype_to_str(16) == 'TXT', rrtype_to_str(16)

        assert opcode_to_str(0) == 'QUERY', opcode_to_str(0)
        # libwdns doesnt have str_to_opcode

        assert rcode_to_str(3) == 'NXDOMAIN', rcode_to_str(3)
        assert str_to_rcode('NXDOMAIN') == 3, str_to_rcode('NXDOMAIN')

        assert rrclass_to_str(1) == 'IN', rrclass_to_str(1)
        assert str_to_rrclass('IN') == 1, str_to_rrclass('IN')

    def test_txt_record_creation(self):
        assert rdata_to_str(
            b'\x10text record data', TYPE_TXT, CLASS_IN) == \
            '"text record data"', rdata_to_str(
                b'\x10text record data', TYPE_TXT, CLASS_IN)
        assert str_to_rdata('"text record data"', TYPE_TXT, CLASS_IN) == \
            b'\x10text record data',\
            str_to_rdata('"text record data"', TYPE_TXT, CLASS_IN)

    def test_str_to_name_case(self):
        domain = 'FsI.iO'
        name = str_to_name_case(domain)
        assert name == b'\x03FsI\x02iO\x00', name

    def test_len_name(self):
        domain = 'FsI.iO'
        name = str_to_name_case(domain)
        assert len_name(name) == len(name)

    def test_parse_pkt_query(self):
        a = '1bb00100000100000000000006676f6f676c6503636f6d0000010001'
        try:
            b = bytes.fromhex(a)
        except:
            b = a.decode('hex')
        c = parse_message(b)
        assert c.qr is False
        assert str(c.sec[0][0]) == 'google.com. IN A', c.sec[0][0]

    def test_parse_pkt_response(self):
        a = ('1bb08180000100010000000006676f6f676c6503636f6d0000010001c00c0001'
             '00010000012b0004acd9036e')
        try:
            b = bytes.fromhex(a)
        except:
            b = a.decode('hex')
        c = parse_message(b)
        assert c.qr is True
        assert str(c.sec[0][0]) == 'google.com. IN A', c.sec[0][0]
        assert str(c.sec[1][0]) == 'google.com. 299 IN A 172.217.3.110', \
                                    c.sec[1][0]


if __name__ == '__main__':
    unittest.main()
