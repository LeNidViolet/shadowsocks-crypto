

#pragma once

#pragma pack(push, 1)

typedef struct _DNS_HEADER{
	unsigned short		Xid;

	unsigned char		RecursionDesired : 1;
	unsigned char		Truncation : 1;			// 数据包是被截断的
	unsigned char		Authoritative : 1;
	unsigned char		Opcode : 4;
	unsigned char		IsResponse : 1;

	unsigned char		ResponseCode : 4;
	unsigned char		CheckingDisabled : 1;
	unsigned char		AuthenticatedData : 1;
	unsigned char		Reserved : 1;
	unsigned char		RecursionAvailable : 1;

	unsigned short		QuestionCount;
	unsigned short		AnswerCount;
	unsigned short		NameServerCount;
	unsigned short		AdditionalCount;
}DNS_HEADER, *PDNS_HEADER;

//  DNS Question

typedef struct _DNS_WIRE_QUESTION{
	//  Preceded by question name

	unsigned short		QuestionType;
	unsigned short		QuestionClass;
}DNS_WIRE_QUESTION, *PDNS_WIRE_QUESTION;


//  DNS Resource Record

typedef struct _DNS_WIRE_RECORD{
	//  Preceded by record owner name

	unsigned short		RecordType;
	unsigned short		RecordClass;
	unsigned int		TimeToLive;
	unsigned short		DataLength;

	//  Followed by record data
}DNS_WIRE_RECORD, *PDNS_WIRE_RECORD;

#pragma pack(pop)

#ifndef DNS_MAXDN
#define DNS_MAXDN	255	/* max DN length */
#endif

#define DNS_QUERY_TYPE_IPV4		1
#define DNS_QUERY_TYPE_IPV6		28

typedef struct DNS_ANSWER_{
	char						name[DNS_MAXDN];
	unsigned short				type;
	unsigned short				_class;
	unsigned int				ttl;
	unsigned short				rdataLen;

	union
	{
		char			data[DNS_MAXDN];
		unsigned int	ip;
		unsigned char	ipV6[16];
	}rdata;
}DNS_ANSWER, *PDNS_ANSWER;



typedef struct DNS_PARSE_{
	DNS_HEADER			dnsHdr;

	char				queryDomain[DNS_MAXDN];
	unsigned short		queryType;
	unsigned short		queryClass;

	unsigned int		parseLen;

	unsigned short		answerCount;
	PDNS_ANSWER			answers;
}DNS_PARSE, *PDNS_PARSE;


PDNS_PARSE ParseDnsRecord(const char* data, unsigned int dataLen);

unsigned int ByteswapUInt32(unsigned int i);
unsigned short ByteswapUshort(unsigned short i);
