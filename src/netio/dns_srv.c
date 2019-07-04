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
#include "dns_cache.h"
#include "internal.h"
#include "udns/parsedns.h"


typedef struct {
    char buf[512];

    char domain[64];
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
} dns_block;


static const int dns_udp_handle_max = 8;
static int dns_udp_handle_index = 0;
static uv_udp_t *dns_udp_handles[dns_udp_handle_max];

static uv_signal_t dns_signal_handle;
static int dns_signal_inited = 0;


static void dnssrv_signal_cb(uv_signal_t* handle, int signum) {
    (void)handle;
    (void)signum;

    dns_server_stop();
}

/* 注册信号 */
static int dnssrv_signal_setup(uv_loop_t *loop) {
    int ret;

    if ( dns_signal_inited ) {
        ret = 0;
        BREAK_NOW;
    }

    ret = uv_signal_init(loop, &dns_signal_handle);
    CHECK(0 == ret);

    uv_signal_start(&dns_signal_handle, dnssrv_signal_cb, SIGINT);
    uv_signal_start(&dns_signal_handle, dnssrv_signal_cb, SIGTERM);

    dns_signal_inited = 1;
BREAK_LABEL:

    return ret;
}

static void dnssrv_signal_close_done(uv_handle_t* handle) {
    (void)handle;
}

static void dnssrv_signal_close() {
    if ( dns_signal_inited ) {
        uv_signal_stop(&dns_signal_handle);
        uv_close((uv_handle_t*)&dns_signal_handle, dnssrv_signal_close_done);
        dns_signal_inited = 0;
    }
}


static void dnssrv_alloc_cb(
    uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {

    (void)handle;
    suggested_size = sizeof(dns_block);
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
    memset(buf->base, 0, suggested_size);
}


void dnssrv_send_done(uv_udp_send_t *req, int status) {
    dns_block *block;

    (void)status;
    block = CONTAINER_OF(req, dns_block, req.send_req);

    free(block);
}


static void dnssrv_response(
    dns_block *block,
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
    record->RecordType  = ByteswapUshort(block->query_type);
    record->RecordClass = ByteswapUshort((unsigned short)1); // CLASS IN
    record->TimeToLive  = ByteswapUInt32((unsigned int)12);
    record->DataLength  = ByteswapUshort(block->query_type == DNS_QUERY_TYPE_IPV4 ?
                                        (unsigned short)4 : (unsigned short)16);

    pos = (char*)(record + 1);
    if ( DNS_QUERY_TYPE_IPV4 == block->query_type ) {
        struct sockaddr_in *addr_ipv4 = (struct sockaddr_in *)result;
        *(unsigned int*)pos = addr_ipv4->sin_addr.s_addr;

        response_len = block->query_len + 2 + sizeof(DNS_WIRE_RECORD) + 4;
    } else {
        struct sockaddr_in6 *addr_ipv6 = (struct sockaddr_in6 *)result;
        memcpy(pos, &addr_ipv6->sin6_addr, 16);

        response_len = block->query_len + 2 + sizeof(DNS_WIRE_RECORD) + 16;
    }

    sndbuf = uv_buf_init(block->buf, response_len);

    int ret = uv_udp_send(
        &block->req.send_req,
        block->handle,
        &sndbuf,
        1,
        &block->client_addr.addr,
        dnssrv_send_done);
    if ( 0 == ret ) {

    } else {
        free(block);
    }
}


static void dnssrv_getaddrinfo_done(
    uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {

    struct addrinfo *ai;
    struct addrinfo *ai_ipv4 = NULL;
    struct addrinfo *ai_ipv6 = NULL;
    dns_block *block = NULL;

    block = CONTAINER_OF(req, dns_block, req);

    if ( 0 == status ) {
        for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
            dns_cache_add(block->domain, ai->ai_addr);

            if ( AF_INET == ai->ai_family && !ai_ipv4 ) {
                ai_ipv4 = ai;
            }
            if ( AF_INET6 == ai->ai_family && !ai_ipv6 ) {
                ai_ipv6 = ai;
            }
        }

        if ( block->query_type == DNS_QUERY_TYPE_IPV4 && ai_ipv4 ) {
            dnssrv_response(block, ai_ipv4->ai_addr);
        } else if ( block->query_type == DNS_QUERY_TYPE_IPV6 && ai_ipv6 ) {
            dnssrv_response(block, ai_ipv6->ai_addr);
        } else {
            // impossible
            free(block);
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
    struct sockaddr* addr;
    int req_ipv4;
    dns_block *block = NULL;
    int lookup = 1;
    struct addrinfo hints;

    (void)flags;

    if ( nread <= 0 || !clientaddr )
        BREAK_NOW;

    block = (dns_block *)buf->base;
    ASSERT(nread < sizeof(block->buf) - 64);
    block->query_len = (unsigned int)nread;

    parse = ParseDnsRecord(buf->base, block->query_len);
    if ( !parse ) {
        ssnetio_on_msg(1, "dns record parse failed length[%d]", block->query_len);
        BREAK_NOW;
    }

    // TODO: ONLY CLASS IN + IPV4 IPV6 ONLY FOR NOW
    if ( parse->queryClass != 1 ||
        (parse->queryType != DNS_QUERY_TYPE_IPV4 && parse->queryType != DNS_QUERY_TYPE_IPV6) ) {

        ssnetio_on_msg(
            1,
            "unknow dns queryclass[%d] or querytype[%d]",
            parse->queryClass,
            parse->queryType);
        BREAK_NOW;
    }

    block->handle = handle;
    block->query_type = parse->queryType;
    sockaddr_cpy(clientaddr, &block->client_addr.addr);

    req_ipv4 = DNS_QUERY_TYPE_IPV4 == parse->queryType ? 1 : 0;

    // 首先从缓存中查找
    addr = dns_cache_find_ip(parse->queryDomain, req_ipv4);
    if ( addr ) {
        dnssrv_response(block, addr);
        lookup = 0;
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
            ssnetio_on_msg(1, "dns uv_getaddrinfo failed [%s]", block->domain);
            BREAK_NOW;
        }
    }

    block = NULL;
BREAK_LABEL:

    if ( parse ) free(parse);
    if ( block ) free(block);
}

static int dnssrv_read_local(uv_udp_t *handle) {
    return uv_udp_recv_start(handle, dnssrv_alloc_cb, dnssrv_read_done);
}

static void dnssrv_handle_close_done(uv_handle_t* handle) {
    if ( handle ) {
        free(handle);
    }
}

static void dnssrv_handle_close(uv_udp_t *handle) {
    if ( handle ) {
        uv_udp_recv_stop(handle);
        uv_close((uv_handle_t*)handle, dnssrv_handle_close_done);
    }
}


int dns_server_launch(uv_loop_t *loop, const struct sockaddr *addr) {
    uv_udp_t *udp_handle = NULL;
    struct sockaddr_in ipv4_addr;
    int local_loop = 0;
    int ret = -1;
    const unsigned short dns_port = 53;

    if ( dns_udp_handle_index >= dns_udp_handle_max ) BREAK_NOW;

    if ( !loop ) {
        loop = uv_default_loop();
        local_loop = 1;
    }

    if ( !addr ) {
        uv_ip4_addr("0.0.0.0", dns_port, &ipv4_addr);
        addr = (const struct sockaddr*)&ipv4_addr;
    }

    ENSURE((udp_handle = malloc(sizeof(*udp_handle))) != NULL);
    CHECK(0 == uv_udp_init(loop, udp_handle));

    dns_cache_init();

    ret = uv_udp_bind(udp_handle, addr, 0);
    BREAK_ON_FAILURE(ret);

    CHECK(0 == dnssrv_read_local(udp_handle));

    dns_udp_handles[dns_udp_handle_index++] = udp_handle;
    udp_handle = NULL;

    dnssrv_signal_setup(loop);

    if ( local_loop ) {
        ret = uv_run(loop, UV_RUN_DEFAULT);
        uv_loop_close(loop);
    }

BREAK_LABEL:

    if ( udp_handle ) {
        dnssrv_handle_close(udp_handle);
    }

    return ret;
}

void dns_server_stop() {

    for ( int i = 0; i < dns_udp_handle_max; ++i ) {
        if ( dns_udp_handles[i] ) {
            dnssrv_handle_close(dns_udp_handles[i]);
        }
    }

    memset(dns_udp_handles, 0, sizeof(dns_udp_handles));
    dns_udp_handle_index = 0;

    dnssrv_signal_close();
    dns_cache_clear();

    printf("dns server exited\n");
}
