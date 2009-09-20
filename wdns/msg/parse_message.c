#include "private.h"

wdns_msg_status
wdns_parse_message(const uint8_t *op, const uint8_t *eop, wdns_message_t *m)
{
	const uint8_t *p = op;
	size_t rrlen;
	uint16_t sec_counts[WDNS_MSG_SEC_MAX];
	uint32_t len = eop - op;
	wdns_rr_t rr;
	wdns_msg_status status;

	memset(m, 0, sizeof(*m));

	if (len < WDNS_LEN_HEADER) {
		VERBOSE("op=%p eop=%p\n", op, eop);
		WDNS_ERROR(wdns_msg_err_len);
	}

	WDNS_BUF_GET16(m->id, p);
	WDNS_BUF_GET16(m->flags, p);
	WDNS_BUF_GET16(sec_counts[WDNS_MSG_SEC_QUESTION], p);
	WDNS_BUF_GET16(sec_counts[WDNS_MSG_SEC_ANSWER], p);
	WDNS_BUF_GET16(sec_counts[WDNS_MSG_SEC_AUTHORITY], p);
	WDNS_BUF_GET16(sec_counts[WDNS_MSG_SEC_ADDITIONAL], p);

	len -= WDNS_LEN_HEADER;

	VERBOSE("Parsing DNS message id=%#.2x flags=%#.2x\n", m->id, m->flags);

	for (unsigned sec = 0; sec < WDNS_MSG_SEC_MAX; sec++) {
		for (unsigned n = 0; n < sec_counts[sec]; n++) {
#if DEBUG
			switch (sec) {
			case WDNS_MSG_SEC_QUESTION:
				VERBOSE("QUESTION RR %zd\n", n);
				break;
			case WDNS_MSG_SEC_ANSWER:
				VERBOSE("ANSWER RR %zd\n", n);
				break;
			case WDNS_MSG_SEC_AUTHORITY:
				VERBOSE("AUTHORITY RR %zd\n", n);
				break;
			case WDNS_MSG_SEC_ADDITIONAL:
				VERBOSE("ADDITIONAL RR %zd\n", n);
				break;
			}
#endif
			status = wdns_parse_message_rr(sec, op, eop, p, &rrlen, &rr);
			if (status != wdns_msg_success) {
				wdns_clear_message(m);
				WDNS_ERROR(wdns_msg_err_parse_error);
			}
			status = wdns_insert_rr_rrset_array(&rr, &m->sections[sec]);
			if (status != wdns_msg_success)
				goto err;
			p += rrlen;
		}
	}

	return (wdns_msg_success);
err:
	wdns_clear_rr(&rr);
	wdns_clear_message(m);
	WDNS_ERROR(status);
}
