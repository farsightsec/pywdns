include "pywreck.pxi"

def WreckException(Exception):
    pass

def domain_to_str(char *src):
    cdef char *dst
    dst = <char *> malloc(len(src) + 1)
    wreck_domain_to_str(<uint8_t *> src, dst)
    return dst

def parse_message(bytes pkt):
    cdef wreck_dns_message_t m
    cdef wreck_dns_rdata_t *rdata
    cdef wreck_dns_rrset_t *rrset
    cdef wreck_dns_rrset_array_t *a
    cdef wreck_msg_status status
    cdef uint8_t *op

    op = <uint8_t *> PyString_AsString(pkt)
    if op == NULL:
        raise Exception('PyString_AsString() failed')

    status = wreck_parse_message(op, op + PyString_Size(pkt), &m)
    if status == wreck_msg_success:
        qname = PyString_FromStringAndSize(<char *> m.question.name.data, m.question.name.len)
        question = (qname, m.question.rrclass, m.question.rrtype)

        secs = [ [], [], [] ]
        for i from 0 <= i < 3:
            a = &m.sections[i]
            for j from 0 <= j < a.n_rrsets:
                rrset = a.rrsets[j]
                name = PyString_FromStringAndSize(<char *> rrset[0].name.data, rrset[0].name.len)
                rdata_list = []
                for k from 0 <= k < rrset.n_rdatas:
                    rdata = rrset[0].rdatas[k]
                    py_rdata = PyString_FromStringAndSize(<char *> rdata.data, rdata.len)
                    rdata_list.append(py_rdata)
                secs[i].append((name, rrset.rrclass, rrset.rrtype, rrset.rrttl, rdata_list))

        wreck_dns_message_clear(&m)
        return (m.id, m.flags, question, secs[0], secs[1], secs[2])
    else:
        raise WreckException('wreck_parse_message() returned %s' % status)