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
from wdns import *


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
        assert rdata_to_str(b'\x10text record data', TYPE_TXT, CLASS_IN) == '"text record data"', \
            rdata_to_str(b'\x10text record data', TYPE_TXT, CLASS_IN)
        assert str_to_rdata('"text record data"', TYPE_TXT, CLASS_IN) == b'\x10text record data',\
            str_to_rdata('"text record data"', TYPE_TXT, CLASS_IN)

    def test_str_to_name_case(self):
        domain = 'FsI.iO'
        name = str_to_name_case(domain)
        assert name == b'\x03FsI\x02iO\x00', name

if __name__ == '__main__':
    unittest.main()