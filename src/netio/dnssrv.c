/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2019-03-13.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include "uv.h"
#include "dnsc.h"
#include "internal.h"
#include "udns/parsedns.h"


typedef struct DNSSRV_MEM_BLOCK_{
    char buf[512];

    char domain[256];
    unsigned short query_type;
    unsigned int query_len;
    union {
        uv_getaddrinfo_t dns_req;
        uv_udp_send_t send_req;
    }req;

    union{
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    }client_addr;

    uv_udp_t *handle;
} DNSSRV_MEM_BLOCK;



static void dnssrv_alloc_cb(
    uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {

    (void)handle;
    suggested_size = sizeof(DNSSRV_MEM_BLOCK);
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
    memset(buf->base, 0, suggested_size);
}


void dnssrv_send_done(uv_udp_send_t *req, int status) {
    DNSSRV_MEM_BLOCK *block;

    block = CONTAINER_OF(req, DNSSRV_MEM_BLOCK, req.send_req);

    if ( 0 != status ) {

    }

//    free(block);
}


static void dnssrv_response(
    DNSSRV_MEM_BLOCK *block,
    const struct sockaddr *result) {

    PDNS_HEADER hdr = (PDNS_HEADER)block->buf;
    char *pos;
    PDNS_WIRE_RECORD record;
    unsigned int response_len;
    uv_buf_t sndbuf;

    hdr->IsResponse = 1;
    hdr->RecursionAvailable = 1;
    hdr->AnswerCount = ByteswapUshort((unsigned short)1);

    pos = (char*)hdr + (int)block->query_len;
    *(unsigned short*)pos = 0x0CC0;
    pos += 2;

    record = (PDNS_WIRE_RECORD)pos;
    record->RecordType = ByteswapUshort(block->query_type);
    record->RecordClass = ByteswapUshort((unsigned short)1); // CLASS IN
    record->TimeToLive = ByteswapUInt32((unsigned int)12);
    record->DataLength = ByteswapUshort(block->query_type == DNS_QUERY_TYPE_IPV4 ?
                                        (unsigned short)4 : (unsigned short)16);

    pos = (char*)(record + 1);
    if ( block->query_type == DNS_QUERY_TYPE_IPV4 ) {
        struct sockaddr_in *addr_ipv4 = (struct sockaddr_in *)result;
        *(unsigned int*)pos = addr_ipv4->sin_addr.s_addr;

        response_len = block->query_len + 2 + sizeof(DNS_WIRE_RECORD) + 4;
    } else {
        struct sockaddr_in6 *addr_ipv6 = (struct sockaddr_in6 *)result;
        memcpy(pos, &addr_ipv6->sin6_addr, 16);

        response_len = block->query_len + 2 + sizeof(DNS_WIRE_RECORD) + 16;
    }

    sndbuf = uv_buf_init(block->buf, response_len);
    if( uv_udp_send(
        &block->req.send_req,
        block->handle,
        &sndbuf,
        1,
        &block->client_addr.addr,
        dnssrv_send_done)) {


    } else {
        printf("uv_udp_send failed\n");
        free(block);
    }
}


static void dnssrv_getaddrinfo_done(
    uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {

    struct addrinfo *ai;
    struct addrinfo *ai_ipv4 = NULL;
    struct addrinfo *ai_ipv6 = NULL;
    DNSSRV_MEM_BLOCK *block = NULL;

    block = CONTAINER_OF(req, DNSSRV_MEM_BLOCK, req);

    if ( 0 == status ) {
        for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
            if ( AF_INET == ai->ai_family && !ai_ipv4 ) {
                ai_ipv4 = ai;
            }
            if ( AF_INET6 == ai->ai_family && !ai_ipv6 ) {
                ai_ipv6 = ai;
            }
        }

        printf("DNS RESOLVE GETADDR DONE: %s\n", block->domain);

        dnsc_add(
            block->domain,
            ai_ipv4 ? ai_ipv4->ai_addr : NULL,
            ai_ipv6 ? ai_ipv6->ai_addr : NULL);

        if ( block->query_type == DNS_QUERY_TYPE_IPV4 && ai_ipv4 ) {
            dnssrv_response(block, ai_ipv4->ai_addr);

        } else if ( block->query_type == DNS_QUERY_TYPE_IPV6 && ai_ipv6 ) {
            dnssrv_response(block, ai_ipv6->ai_addr);

        }
    } else {
        free(block);
    }

    uv_freeaddrinfo(addrs);
}

static void dnssrv_read_done(
    uv_udp_t *handle,
    ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *clientaddr,
    unsigned flags) {

    DNS_PARSE *parse = NULL;
    uv_loop_t *loop;
    DNSC *cache = NULL;
    DNSSRV_MEM_BLOCK *block = NULL;
    int lookup = 1;
    struct addrinfo hints;

    (void)flags;

    if ( nread <= 0 || !clientaddr )
        BREAK_NOW;

    block = (DNSSRV_MEM_BLOCK *)buf->base;
    ASSERT(nread < sizeof(block->buf) - 64);
    block->query_len = (unsigned int)nread;

    parse = ParseDnsRecord(buf->base, block->query_len);
    if ( !parse ) {
        ssnetio_on_msg(1, "Dns Record Parse Failed Length[%d]", block->query_len);
        BREAK_NOW;
    }

    printf("DNS RESOLVE BEGIN: %s\n", parse->queryDomain);

    // TODO: ONLY CLASS IN + IPV4 IPV6 ONLY FOR NOW
    if ( parse->queryClass != 1 ||
        (parse->queryType != DNS_QUERY_TYPE_IPV4 && parse->queryType != DNS_QUERY_TYPE_IPV6) ) {

        ssnetio_on_msg(1, "Unknow Dns QueryClass[%d] or QueryType[%d]", parse->queryClass, parse->queryType);
        BREAK_NOW;
    }

    block->handle = handle;
    block->query_type = parse->queryType;
    cpy_sockaddr(clientaddr, &block->client_addr.addr);

    cache = dnsc_find(parse->queryDomain);
    if ( cache ) {
        if ( parse->queryType == DNS_QUERY_TYPE_IPV4 && cache->ipv4_valid ) {
            printf("DNS RESOLVE CACHE IPV4: %s\n", parse->queryDomain);

            dnssrv_response(block, &cache->ipv4.addr);
            lookup = 0;
        } else if ( parse->queryType == DNS_QUERY_TYPE_IPV6 && cache->ipv6_valid ) {
            printf("DNS RESOLVE CACHE IPV6: %s\n", parse->queryDomain);

            dnssrv_response(block, &cache->ipv6.addr);
            lookup = 0;
        }
    }

    if ( lookup ) {
        loop = uv_handle_get_loop((uv_handle_t*)handle);

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        strcpy(block->domain, parse->queryDomain);

        if ( 0 != uv_getaddrinfo(loop,
                                 &block->req.dns_req,
                                 dnssrv_getaddrinfo_done,
                                 parse->queryDomain,
                                 NULL,
                                 &hints) ) {
            ssnetio_on_msg(1, "Dns uv_getaddrinfo Failed [%s]", block->domain);
            BREAK_NOW;
        }
    }

    block = NULL;
BREAK_LABEL:

    if ( parse ) free(parse);
    if ( block ) free(block);
}

int dnssrv_read_local(uv_udp_t *handle) {
    return uv_udp_recv_start(handle, dnssrv_alloc_cb, dnssrv_read_done);
}
