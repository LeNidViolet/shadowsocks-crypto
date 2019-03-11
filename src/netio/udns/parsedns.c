
#include <stdlib.h>
#include <string.h>
#include "udns.h"
#include "parsedns.h"
#include "shadowsocks-crypto/comm.h"

unsigned int ByteswapUInt32(unsigned int i) {
	unsigned int j;
	j = (i << 24);
	j += (i << 8) & 0x00FF0000;
	j += (i >> 8) & 0x0000FF00;
	j += (i >> 24);
	return j;
}

unsigned short ByteswapUshort(unsigned short i) {
	unsigned short j;
	j = (i << 8);
	j += (i >> 8);
	return j;
}


PDNS_PARSE ParseDnsRecord(const char* data, unsigned long dataLen) {

	PDNS_PARSE			result = NULL;
	int					errCode = -1;

	struct dns_parse parse = { 0 };

	if ( !data || dataLen < sizeof(DNS_HEADER) ) BREAK_NOW;

	PDNS_HEADER hdr = (PDNS_HEADER)data;
	if ( hdr->Truncation ) BREAK_NOW;

	unsigned short questionCount = ByteswapUshort(hdr->QuestionCount);
	unsigned short answerCount = ByteswapUshort(hdr->AnswerCount);
	if ( questionCount != 1 ) BREAK_NOW;

	unsigned char dn[DNS_MAXDN] = {0};
	const unsigned char *pkt, *cur, *end;
	pkt = (unsigned char*)data;
	end = (unsigned char*)(data + dataLen);
	cur = dns_payload(pkt);

	int ret = dns_getdn(pkt, &cur, end, dn, sizeof(dn));
	if ( ret <= 0 ) BREAK_NOW;

	unsigned int totalLen = sizeof(DNS_PARSE) + answerCount * sizeof(DNS_ANSWER);
	result = (PDNS_PARSE)calloc(1, totalLen);
	BREAK_ON_NULL(result);

	result->parseLen = totalLen;

	memcpy(&result->dnsHdr, hdr, sizeof(DNS_HEADER));
	result->dnsHdr.Xid = ByteswapUshort(result->dnsHdr.Xid);
	result->dnsHdr.QuestionCount = ByteswapUshort(result->dnsHdr.QuestionCount);
	result->dnsHdr.AnswerCount = ByteswapUshort(result->dnsHdr.AnswerCount);
	result->dnsHdr.NameServerCount = ByteswapUshort(result->dnsHdr.NameServerCount);
	result->dnsHdr.AdditionalCount = ByteswapUshort(result->dnsHdr.AdditionalCount);

	ret = dns_dntop(dn, result->queryDomain, sizeof(result->queryDomain));
	if ( ret <= 0 ) BREAK_NOW;

	PDNS_WIRE_QUESTION question = (PDNS_WIRE_QUESTION)cur;
	result->queryType = ByteswapUshort(question->QuestionType);
	result->queryClass = ByteswapUshort(question->QuestionClass);

	if ( (result->queryType != DNS_T_A) && (result->queryType != DNS_T_AAAA) ) BREAK_NOW;


	if ( answerCount > 0 ) {
		result->answers = (PDNS_ANSWER)((char*)result + sizeof(DNS_PARSE));

		dns_initparse(&parse, NULL, pkt, cur, end);

		parse.dnsp_qcls = DNS_C_INVALID;
		parse.dnsp_qtyp = DNS_T_INVALID;

		PDNS_ANSWER thisAnswer = result->answers;
		for ( int i = 0; i < answerCount; i++ ) {
			struct dns_rr		rr = { 0 };
			int rrret = dns_nextrr(&parse, &rr);

			if (
				rr.dnsrr_cls == DNS_C_IN &&
				(rr.dnsrr_typ == DNS_T_A || rr.dnsrr_typ == DNS_T_CNAME || rr.dnsrr_typ == DNS_T_AAAA)
				) {
				thisAnswer->type = (unsigned short)rr.dnsrr_typ;
				thisAnswer->_class = (unsigned short)rr.dnsrr_cls;
				thisAnswer->ttl = (unsigned int)rr.dnsrr_ttl;
				thisAnswer->rdataLen = (unsigned short)rr.dnsrr_dsz;

				ret = dns_dntop(rr.dnsrr_dn, thisAnswer->name, sizeof(thisAnswer->name));
				if ( ret > 0 ) {
					if ( rr.dnsrr_typ == DNS_T_A ) {
						if ( rr.dnsrr_dsz == sizeof(unsigned int) ) {
							thisAnswer->rdata.ip = *(unsigned int*)rr.dnsrr_dptr;
							thisAnswer->rdata.ip = ByteswapUInt32(thisAnswer->rdata.ip);

							thisAnswer++;
							result->answerCount++;
						}
					}
					else if ( rr.dnsrr_typ == DNS_T_CNAME ) {
						memset(dn, 0, sizeof(dn));
						cur = rr.dnsrr_dptr;
						ret = dns_getdn(pkt, &cur, end, dn, sizeof(dn));
						if ( ret > 0 ) {
							ret = dns_dntop(dn, thisAnswer->rdata.data, sizeof(thisAnswer->rdata.data));
							if ( ret > 0 ) {
								thisAnswer++;
								result->answerCount++;
							}
						}
					}
					else if ( rr.dnsrr_typ == DNS_T_AAAA ) {
						if ( rr.dnsrr_dsz == 16 ) {
							memcpy(thisAnswer->rdata.ipV6, rr.dnsrr_dptr, 16);

							thisAnswer++;
							result->answerCount++;
						}
					}
				}
			}

			if ( rrret == 0 ) break;
		}
	}

	errCode = 0;

BREAK_LABEL:

	if ( errCode != 0 ) {
		if ( result )
			free(result);
		result = NULL;
	}

	return result;
}
