

#pragma once


typedef unsigned long	DWORD;
typedef unsigned short	WORD;
typedef unsigned char	BYTE;



#pragma pack(push, 1)

typedef struct _DNS_HEADER{
	WORD    Xid;

	BYTE    RecursionDesired : 1;
	BYTE    Truncation : 1;
	BYTE    Authoritative : 1;
	BYTE    Opcode : 4;
	BYTE    IsResponse : 1;

	BYTE    ResponseCode : 4;
	BYTE    CheckingDisabled : 1;
	BYTE    AuthenticatedData : 1;
	BYTE    Reserved : 1;
	BYTE    RecursionAvailable : 1;

	WORD    QuestionCount;
	WORD    AnswerCount;
	WORD    NameServerCount;
	WORD    AdditionalCount;
}DNS_HEADER, *PDNS_HEADER;


#define DNS_HEADER_FLAGS(pHead)     ( *((PWORD)(pHead)+1) )

#define DNS_OFFSET_TO_QUESTION_NAME     sizeof(DNS_HEADER)

//  Question immediately follows header so compressed question name
//      0xC000 | sizeof(DNS_HEADER)

#define DNS_COMPRESSED_QUESTION_NAME  (0xC00C)



//  Packet extraction macros
#define DNS_QUESTION_NAME_FROM_HEADER( _pHeader_ ) \
            ( (PCHAR)( (PDNS_HEADER)(_pHeader_) + 1 ) )




//  DNS Question

typedef struct _DNS_WIRE_QUESTION{
	//  Preceded by question name

	WORD    QuestionType;
	WORD    QuestionClass;
}DNS_WIRE_QUESTION, *PDNS_WIRE_QUESTION;


//  DNS Resource Record

typedef struct _DNS_WIRE_RECORD{
	//  Preceded by record owner name

	WORD    RecordType;
	WORD    RecordClass;
	DWORD   TimeToLive;
	WORD    DataLength;

	//  Followed by record data
}DNS_WIRE_RECORD, *PDNS_WIRE_RECORD;

#pragma pack(pop)

#ifndef DNS_MAXDN
#define DNS_MAXDN	255	/* max DN length */
#endif

typedef struct DNS_ANSWER_{
	char				name[DNS_MAXDN];
	WORD				type;
	WORD				_class;
	DWORD				ttl;
	WORD				rdataLen;

	union
	{
		char			data[DNS_MAXDN];
		DWORD			ip;
	}rdata;
}DNS_ANSWER, *PDNS_ANSWER;



typedef struct DNS_PARSE_{
	DNS_HEADER			dnsHdr;

	char				queryDomain[DNS_MAXDN];
	WORD				queryType;
	WORD				queryClass;

	DWORD				parseLen;
	
	WORD				answerCount;
	PDNS_ANSWER			answers;
}DNS_PARSE, *PDNS_PARSE;


PDNS_PARSE ParseDnsRecord(const char* Buffer, unsigned long BufferLen);
