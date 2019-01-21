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

from libcpp cimport bool
from libc.stddef cimport *
from libc.stdint cimport *
from libc.stdio cimport *
from libc.stdlib cimport *
from libc.string cimport *

cdef extern from "wdns.h":
    enum:
        WDNS_LEN_HEADER
        WDNS_MAXLEN_NAME

        WDNS_PRESLEN_NAME
        WDNS_PRESLEN_TYPE_A
        WDNS_PRESLEN_TYPE_AAAA

    ctypedef enum wdns_res:
        wdns_res_success
        wdns_res_invalid_compression_pointer
        wdns_res_invalid_length_octet
        wdns_res_invalid_opcode
        wdns_res_invalid_rcode
        wdns_res_len
        wdns_res_malloc
        wdns_res_name_len
        wdns_res_name_overflow
        wdns_res_out_of_bounds
        wdns_res_overflow
        wdns_res_parse_error
        wdns_res_qdcount
        wdns_res_unknown_opcode
        wdns_res_unknown_rcode

    ctypedef struct wdns_name_t:
        uint8_t             len
        uint8_t             *data

    ctypedef struct wdns_rdata_t:
        uint16_t            len
        uint8_t             data[0]

    ctypedef struct wdns_rr_t:
        uint32_t            rrttl
        uint16_t            rrtype
        uint16_t            rrclass
        wdns_name_t         name
        wdns_rdata_t        *rdata

    ctypedef struct wdns_rrset_t:
        uint32_t            rrttl
        uint16_t            rrtype
        uint16_t            rrclass
        uint16_t            n_rdatas
        wdns_name_t         name
        wdns_rdata_t        **rdatas

    ctypedef struct wdns_rrset_array_t:
        uint16_t            n_rrsets
        wdns_rrset_t        *rrsets

    ctypedef struct wdns_edns_t:
        int                 present
        uint8_t             version
        uint16_t            flags
        uint16_t            size
        wdns_rdata_t        *options

    ctypedef struct wdns_message_t:
        wdns_rrset_array_t  sections[4]
        wdns_edns_t         edns
        uint16_t            id
        uint16_t            flags
        uint16_t            rcode

    const char *      wdns_opcode_to_str(uint16_t)
    const char *      wdns_rcode_to_str(uint16_t)
    const char *      wdns_rrclass_to_str(uint16_t)
    const char *      wdns_rrtype_to_str(uint16_t)

    char *      wdns_rdata_to_str(uint8_t *, uint16_t, uint16_t, uint16_t)
    size_t      wdns_domain_to_str(uint8_t *, size_t, char *)
    wdns_res    wdns_str_to_rcode(char *, uint16_t *)
    uint16_t    wdns_str_to_rrtype(char *)
    uint16_t    wdns_str_to_rrclass(char *)
    wdns_res    wdns_str_to_rdata(char *, uint16_t, uint16_t, uint8_t **, size_t *)
    wdns_res    wdns_str_to_name(char *, wdns_name_t *)
    wdns_res    wdns_str_to_name_case(char *, wdns_name_t *)
    wdns_res    wdns_parse_message(wdns_message_t *, uint8_t *, size_t)
    void        wdns_clear_message(wdns_message_t *)
    wdns_res    wdns_reverse_name(uint8_t *, size_t, uint8_t *)
    wdns_res    wdns_len_uname(uint8_t *, uint8_t *, size_t *)
    wdns_res    wdns_left_chop(wdns_name_t *, wdns_name_t *)
    wdns_res    wdns_count_labels(wdns_name_t *, size_t *)
    wdns_res    wdns_is_subdomain(wdns_name_t *, wdns_name_t *, bool *)

    char *      wdns_res_to_str(wdns_res res)
