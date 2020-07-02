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
        self.assertEqual(b'\x03fsi\x02io\x00', name)
        self.assertEqual('fsi.io.', domain_to_str(name))
        rname = reverse_name(name)
        self.assertEqual(b'\x02io\x03fsi\x00', rname)
        self.assertEqual(b'\x02io\x00', left_chop(name))
        self.assertEqual(2, count_labels(name))
        self.assertTrue(is_subdomain(str_to_name('www.' + domain), name))
        self.assertFalse(is_subdomain(name, str_to_name('www.' + domain)))

    def test_opcode_conversions(self):
        self.assertEqual(1, str_to_rrtype('A'))
        self.assertEqual('TXT', rrtype_to_str(16))

        self.assertEqual('QUERY', opcode_to_str(0))
        # libwdns doesnt have str_to_opcode

        self.assertEqual('NXDOMAIN', rcode_to_str(3))
        self.assertEqual(3, str_to_rcode('NXDOMAIN'))

        self.assertEqual('IN', rrclass_to_str(1))
        self.assertEqual(1, str_to_rrclass('IN'))

    def test_txt_record_creation(self):
        self.assertEqual(
            '"text record data"',
            rdata_to_str(b'\x10text record data', TYPE_TXT, CLASS_IN))
        self.assertEqual(
            b'\x10text record data',
            str_to_rdata('"text record data"', TYPE_TXT, CLASS_IN))

    def test_str_to_name_case(self):
        domain = 'FsI.iO'
        name = str_to_name_case(domain)
        self.assertEqual(b'\x03FsI\x02iO\x00', name)

    def test_len_name(self):
        domain = 'FsI.iO'
        name = str_to_name_case(domain)
        self.assertEqual(len(name), len_name(name))

    def test_parse_pkt_query(self):
        a = '1bb00100000100000000000006676f6f676c6503636f6d0000010001'
        try:
            b = bytes.fromhex(a)
        except:
            b = a.decode('hex')
        c = parse_message(b)
        self.assertFalse(c.qr)
        self.assertEqual('google.com. IN A', str(c.sec[0][0]))

    def test_parse_pkt_response(self):
        a = ('1bb08180000100010000000006676f6f676c6503636f6d0000010001c00c0001'
             '00010000012b0004acd9036e')
        try:
            b = bytes.fromhex(a)
        except:
            b = a.decode('hex')
        c = parse_message(b)
        self.assertTrue(c.qr)
        self.assertEqual('google.com. IN A', str(c.sec[0][0]))
        self.assertEqual(
            'google.com. 299 IN A 172.217.3.110',
            str(c.sec[1][0]))


if __name__ == '__main__':
    unittest.main()
