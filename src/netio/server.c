/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/7/26.
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
#include "shadowsocks-crypto/shadowsocks-crypto.h"
#include "internal.h"
#include "dgramsc.h"
#include "dns_cache.h"
#include "udns/parsedns.h"

SSCRYPTO_CTX srv_ctx;

/* 向前声明 */
static int server_run(SSCRYPTO_CTX *ctx);
static void conn_getaddrinfo_done(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);
static int do_handshake(PROXY_NODE *pn);
static int do_req_lookup(PROXY_NODE *pn);
static int do_dnsovertcp_lookup(PROXY_NODE *pn);
static void do_dnsovertcp_packback(PROXY_NODE *pn, struct sockaddr *addr);
static int do_req_connect(PROXY_NODE *pn);
static void dgram_alloc_cb_local(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void dgram_read_done_local(
    uv_udp_t *handle, ssize_t nread,
    const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags
);
static void dgram_send_remote(DGRAMS *dgrams);
static void dgram_send_done_remote(uv_udp_send_t *req, int status);
static void dgram_read_remote(DGRAMS *dgrams);
static void dgram_alloc_cb_remote(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void dgram_read_done_remote(
    uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
    const struct sockaddr *addr, unsigned flags
);
static void dgram_getaddrinfo_done(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);
static void dgram_lookup(DGRAMS *dgrams);
static void dgram_send_local(DGRAMS *dgrams, uv_buf_t *buf);
static void dgram_send_done_local(uv_udp_send_t *req, int status);
static void dgram_timer_reset(DGRAMS *dgrams);
static void dgram_timer_expire(uv_timer_t *handle);


/* 取得NETIO底层操作接口 */
void ssnetio_server_port(IOCTL_PORT *port) {
    port->write_stream_out = ssnetio_write_stream_out;
    port->stream_pause = ssnetio_stream_pause;
}

/* LAUNCHER */
int ssnetio_server_launch(const SSCRYPTO_CTX *ctx) {
    int ret = -1;

    BREAK_ON_NULL(ctx);
    BREAK_ON_NULL(ctx->config.bind_host);
    BREAK_ON_NULL(ctx->config.bind_port);
    BREAK_ON_NULL(ctx->config.idel_timeout);

    dgrams_init();
    dns_cache_init();

    memcpy(&srv_ctx, ctx, sizeof(srv_ctx));
    srv_ctx.config.idel_timeout *= 1000;

    ret = server_run(&srv_ctx);

    dgrams_clear();
    dns_cache_clear();

BREAK_LABEL:

    return ret;
}


static void async_cb(uv_async_t* handle) {
    (void)handle;
    uv_stop(uv_default_loop());
}

void ssnetio_server_stop(void) {
    static uv_async_t uvasync;

    /* 利用 async_t 在 loop 所在线程中去关闭 loop */
    uv_async_init(uv_default_loop(), &uvasync, async_cb);
    uv_async_send(&uvasync);
}

static int server_run(SSCRYPTO_CTX *ctx) {
    struct addrinfo hints;
    uv_loop_t *loop;
    int ret;
    uv_getaddrinfo_t req;

    loop = uv_default_loop();

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    uv_req_set_data((uv_req_t *)&req, loop);
    ret = uv_getaddrinfo(loop,
                         &req,
                         do_bind,
                         ctx->config.bind_host,
                         NULL,
                         &hints);
    if ( 0 != ret ) {
        ssnetio_on_msg(1, "uv_getaddrinfo failed: %s", uv_strerror(ret));
        BREAK_NOW;
    }

    /* Start the event loop.  Control continues in do_bind(). */
    ret = uv_run(loop, UV_RUN_DEFAULT);

    uv_loop_close(loop);

BREAK_LABEL:

    return ret;
}

static void conn_getaddrinfo_done(
    uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    CONN *incoming;
    CONN *outgoing;
    struct addrinfo *ai;
    struct addrinfo *ai_ipv4 = NULL;
    struct addrinfo *ai_ipv6 = NULL;

    outgoing = CONTAINER_OF(req, CONN, t.addrinfo_req);
    ASSERT(outgoing == &outgoing->pn->outgoing);
    outgoing->result = status;

    incoming = &outgoing->pn->incoming;

    if ( 0 == status ) {
        for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
            dns_cache_add(outgoing->peer.host, ai->ai_addr);

            if ( AF_INET == ai->ai_family && !ai_ipv4 ) {
                ai_ipv4 = ai;
            }
            if ( AF_INET6 == ai->ai_family && !ai_ipv6 ) {
                ai_ipv6 = ai;
            }
        }

        cpy_sockaddr(ai_ipv4 ? ai_ipv4->ai_addr : addrs->ai_addr, &outgoing->t.addr);
        set_sockaddr_port(&outgoing->t.addr, htons_u(outgoing->peer.port));
    }

    uv_freeaddrinfo(addrs);

    incoming->pn->outstanding--;
    do_next_server(incoming);
}

void conn_timer_expire_server(uv_timer_t *handle) {
    CONN *conn;
    CONN *incoming;
    CONN *outgoing;

    conn = CONTAINER_OF(handle, CONN, timer_handle);

    incoming = &conn->pn->incoming;
    outgoing = &conn->pn->outgoing;

    switch ( conn->pn->state ) {
    case s_handshake:
        ASSERT(conn == incoming);
        incoming->result = UV_ETIMEDOUT;
        break;
    case s_req_lookup:
    case s_dnsovertcp_lookup:
    case s_req_connect:
    case s_proxy_start:
        outgoing->result = UV_ETIMEDOUT;
        break;

    case s_req_start:
    case s_req_parse:
    case s_proxy_ready:
        UNREACHABLE();
        break;
    default:
        conn->result = UV_ETIMEDOUT; /* s_proxy, .. */
        break;
    }

    do_next_server(conn);
}

void do_next_server(CONN *sender) {
    int new_state = s_max;
    PROXY_NODE *pn = sender->pn;

    ASSERT(pn->state != s_dead);
    switch (pn->state) {
    case s_handshake:
        new_state = do_handshake(pn);
        break;
    case s_req_lookup:
        new_state = do_req_lookup(pn);
        break;
    case s_dnsovertcp_lookup:
        new_state = do_dnsovertcp_lookup(pn);
        break;
    case s_req_connect:
        new_state = do_req_connect(pn);
        break;
    case s_proxy_start:
        new_state = do_proxy_start(pn);
        break;
    case s_proxy:
        new_state = do_proxy(sender);
        break;
    case s_kill:
        new_state = do_kill(pn);
        break;
    case s_almost_dead_0:
    case s_almost_dead_1:
    case s_almost_dead_2:
    case s_almost_dead_3:
    case s_almost_dead_4:
        new_state = do_almost_dead(pn);
        break;
    default:
        UNREACHABLE();
    }
    pn->state = new_state;

    if ( pn->state == s_dead )
        do_clear(pn);
}

static int do_dnsovertcp(PROXY_NODE *pn) {
    CONN *incoming;
    int new_state;
    struct addrinfo hints;
    PDNS_PARSE parse = NULL;
    union{
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } addru;
    struct sockaddr *addrp;

    incoming = &pn->incoming;
    assert(0 != incoming->ss_buf.data_len);

    // DNS OVER TCP 前两字节指示包长
    parse = ParseDnsRecord(
        incoming->ss_buf.data_base + 2,
        (unsigned int)incoming->ss_buf.data_len - 2);
    if ( parse ) {

        strcpy(pn->outgoing.peer.host, parse->queryDomain);

        if ( 0 == uv_ip4_addr(pn->outgoing.peer.host, 53, &addru.addr4) ||
             0 == uv_ip6_addr(pn->outgoing.peer.host, 53, &addru.addr6)) {
            // TODO: IPV4 ONLY FOR NOW
            ASSERT(parse->queryType == DNS_QUERY_TYPE_IPV4);

            do_dnsovertcp_packback(pn, &addru.addr);
            new_state = s_kill;
            BREAK_NOW;
        }

        addrp = dns_cache_find_ip(parse->queryDomain, 1);
        if ( addrp ) {
            // TODO: IPV4 ONLY FOR NOW
            ASSERT(parse->queryType == DNS_QUERY_TYPE_IPV4);

            do_dnsovertcp_packback(pn, addrp);
            new_state = s_kill;
        } else {
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;


            if ( 0 != uv_getaddrinfo(pn->loop,
                                     &pn->outgoing.t.addrinfo_req,
                                     conn_getaddrinfo_done,
                                     parse->queryDomain,
                                     NULL,
                                     &hints) ) {
                new_state = do_kill(pn);
                BREAK_NOW;
            }

            pn->outstanding++;
            conn_timer_reset(&pn->outgoing);

            new_state = s_dnsovertcp_lookup;
        }
    } else {
        new_state = do_kill(pn);
    }

BREAK_LABEL:
    if ( parse )
        free(parse);

    return new_state;
}


static int do_handshake(PROXY_NODE *pn) {
    CONN *incoming;
    int ret, new_state;
    struct addrinfo hints;
    const char *host;
    struct sockaddr* addr;

    incoming = &pn->incoming;

    if ( incoming->result < 0 ) {
        ssnetio_on_msg(1, "%4d Handshake Read Error: %s",
                       pn->index, uv_strerror((int)incoming->result));
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_done == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    incoming->rdstate = c_stop;

    if ( 0 != ssnetio_on_stream_decrypt(incoming, 0) ) {
        ssnetio_on_msg(1, "%4d Handshake Data Decrypt Failed", pn->index);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    /* Parser to get dest address */
    ret = s5_parse_addr(&incoming->ss_buf, &pn->outgoing.peer);
    if ( 0 != ret ) {
        ssnetio_on_msg(1, "%4d Handshake Parse Addr Error", pn->index);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    // 接管DNS查询
    if ( 53 == pn->outgoing.peer.port ) {
        new_state = do_dnsovertcp(pn);
        BREAK_NOW;
    }

    /* Maybe it's a ip address in string form */
    if ( 0 == uv_ip4_addr(pn->outgoing.peer.host, pn->outgoing.peer.port, &pn->outgoing.t.addr4) ||
         0 == uv_ip6_addr(pn->outgoing.peer.host, pn->outgoing.peer.port, &pn->outgoing.t.addr6)) {

        host = dns_cache_find_host(&pn->outgoing.t.addr);
        if ( host ) {
            memset(pn->outgoing.peer.host, 0, sizeof(pn->outgoing.peer.host));
            strcpy(pn->outgoing.peer.host, host);
        }

        new_state = do_req_lookup(pn);
        BREAK_NOW;
    }

    addr = dns_cache_find_ip(pn->outgoing.peer.host, 1);
    if ( !addr ) {
        addr = dns_cache_find_ip(pn->outgoing.peer.host, 0);
    }
    if ( addr ) {
        cpy_sockaddr(addr, &pn->outgoing.t.addr);
        set_sockaddr_port(&pn->outgoing.t.addr, htons_u(pn->outgoing.peer.port));
        new_state = do_req_lookup(pn);

    } else {
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if ( 0 != uv_getaddrinfo(pn->loop,
                                 &pn->outgoing.t.addrinfo_req,
                                 conn_getaddrinfo_done,
                                 pn->outgoing.peer.host,
                                 NULL,
                                 &hints) ) {
            new_state = do_kill(pn);
            BREAK_NOW;
        }

        pn->outstanding++;
        conn_timer_reset(&pn->outgoing);

        new_state = s_req_lookup;
    }

BREAK_LABEL:

    return new_state;
}

static int do_req_lookup(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int ret;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( outgoing->result < 0 ) {
        ssnetio_on_msg(1, "%4d Lookup Error For %s : %s",
                       pn->index,
                       outgoing->peer.host,
                       uv_strerror((int)outgoing->result));

        ret = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_stop == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    ASSERT(c_stop == outgoing->rdstate);
    ASSERT(c_stop == outgoing->wrstate);

    ASSERT(AF_INET == outgoing->t.addr.sa_family ||
           AF_INET6 == outgoing->t.addr.sa_family);

    if ( 0 != uv_tcp_connect(&outgoing->t.connect_req,
                             &outgoing->handle.tcp,
                             &outgoing->t.addr,
                             conn_connect_done) ) {
        ret = do_kill(pn);
        BREAK_NOW;
    }

    pn->outstanding++;
    conn_timer_reset(outgoing);

    ret = s_req_connect;

BREAK_LABEL:

    return ret;
}


static void do_dnsovertcp_packback(PROXY_NODE *pn, struct sockaddr *addr) {
    CONN *incoming = &pn->incoming;
    struct sockaddr_in *addr_v4 = (struct sockaddr_in *)addr;
    unsigned short dnsPktLen;

    // TODO: 组包回发
    dnsPktLen = ByteswapUshort(*(unsigned short*)incoming->ss_buf.data_base);
    PDNS_HEADER hdr = (PDNS_HEADER)(incoming->ss_buf.data_base + 2);
    hdr->IsResponse = 1;
    hdr->RecursionAvailable = 1;
    hdr->AnswerCount = ByteswapUshort(1);

    char* pos = incoming->ss_buf.data_base + dnsPktLen;
    *(unsigned short*)pos = 0x0CC0;
    pos += 2;

    PDNS_WIRE_RECORD record = (PDNS_WIRE_RECORD)pos;
    // TODO: IPV4 ONLY FOR NOW
    record->RecordType = ByteswapUshort(1);
    record->RecordClass = ByteswapUshort(1); // CLASS IN
    record->TimeToLive = ByteswapUInt32(10);
    // TODO: IPV4 ONLY FOR NOW
    record->DataLength = ByteswapUshort(4);

    pos = (char*)(record + 1);
    *(unsigned int*)pos = addr_v4->sin_addr.s_addr;

    // TODO: IPV4 ONLY FOR NOW
    dnsPktLen += 2 + sizeof(DNS_WIRE_RECORD) + 4;
    *(unsigned short*)incoming->ss_buf.data_base = ByteswapUshort(dnsPktLen);

    incoming->ss_buf.data_len = dnsPktLen + 2;

    conn_write(
        incoming,
        incoming->ss_buf.data_base,
        (unsigned int)incoming->ss_buf.data_len);
}

static int do_dnsovertcp_lookup(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int ret;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( outgoing->result < 0 ) {
        ssnetio_on_msg(1, "%4d Lookup Error For %s : %s",
                       pn->index,
                       outgoing->peer.host,
                       uv_strerror((int)outgoing->result));

        ret = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_stop == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    ASSERT(c_stop == outgoing->rdstate);
    ASSERT(c_stop == outgoing->wrstate);

    ASSERT(AF_INET == outgoing->t.addr.sa_family ||
           AF_INET6 == outgoing->t.addr.sa_family);


    do_dnsovertcp_packback(pn, &outgoing->t.addr);
    ret = s_kill;

BREAK_LABEL:

    return ret;
}


static int do_req_connect(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int ret, action;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( 0 != outgoing->result ) {
        ssnetio_on_msg(
            1,
            "%4d Connect to %s:%d failed: %s",
            pn->index,
            outgoing->peer.host,
            outgoing->peer.port,
            uv_strerror((int)outgoing->result));
        ret = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_stop == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    ASSERT(c_stop == outgoing->rdstate);
    ASSERT(c_stop == outgoing->wrstate);

    ssnetio_on_connection_made(pn);

    snprintf(pn->link_info, sizeof(pn->link_info), "%s:%d -> %s:%d",
            incoming->peer.host,
            incoming->peer.port,
            outgoing->peer.host,
            outgoing->peer.port);

    if ( 0 == incoming->ss_buf.data_len ) {
        conn_read(incoming);
        conn_read(outgoing);
        ret = s_proxy;
    } else {
        action = ssnetio_on_plain_stream(incoming);
        switch (action) {
        case PASS:
            break;

        case NEEDMORE:
        case REJECT:
            ret = s_proxy;
            BREAK_NOW;

        case TERMINATE:
            ret = do_kill(pn);
            BREAK_NOW;
        default:
            UNREACHABLE();
        }

        conn_write(
            outgoing,
            incoming->ss_buf.data_base,
            (unsigned int)incoming->ss_buf.data_len);
        ret = s_proxy_start;
    }

BREAK_LABEL:

    return ret;
}



int dgram_read_local(uv_udp_t *handle) {
    return uv_udp_recv_start(handle, dgram_alloc_cb_local, dgram_read_done_local);
}

static void dgram_alloc_cb_local(
    uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    SSNETIO_BUF *ss_buf;

    (void)suggested_size;

    /* Each listening udp handle has an associated buf for recv data */
    ss_buf = uv_handle_get_data(handle);
    buf->base = ss_buf->buf_base;
    buf->len = ss_buf->buf_len;
}

void dgram_read_done_local(
    uv_udp_t *handle, ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    unsigned flags) {

    SSNETIO_BUF *ss_buf;
    ADDRESS srv_addr = {0};
    ADDRESS clt_addr = {0};
    char key[128];
    DGRAMS *dgrams;
    uv_loop_t *loop;

    (void)flags;

    if ( nread <= 0 )
        BREAK_NOW;

    ss_buf = uv_handle_get_data((uv_handle_t*)handle);
    ASSERT(ss_buf->buf_base == buf->base);
    ss_buf->data_base = ss_buf->buf_base;
    ss_buf->data_len = (size_t)nread;

    /* decrypt udp data */
    if ( 0 != ssnetio_on_dgram_decrypt(ss_buf, 0) ) {
        ssnetio_on_msg(1, "Decrypt dgram packet failed");
        BREAK_NOW;
    }
    BREAK_ON_NULL(ss_buf->data_len);

    /* obtain address info */
    if ( 0 != s5_parse_addr(ss_buf, &srv_addr) ) {
        ssnetio_on_msg(1, "Parse dgram packet address failed");
        BREAK_NOW;
    }

    /* Stop recv until all data sent out, or error occur */
    CHECK(0 == uv_udp_recv_stop(handle));

    CHECK(0 == str_sockaddr(addr, &clt_addr));
    /* unique key */
    snprintf(key, sizeof(key), "%s:%d-%s:%d",
        clt_addr.host, clt_addr.port,
        srv_addr.host, srv_addr.port);

    dgrams = dgrams_find_by_key(key);
    if ( dgrams ) {
        /* Already in communication */
        dgram_send_remote(dgrams);
    } else {
        /* Create new one */
        loop = uv_handle_get_loop((uv_handle_t*)handle);

        dgrams = dgrams_add(key, loop);
        dgrams->udp_in = handle;
        cpy_sockaddr(addr, &dgrams->local.addr);
        dgrams->peer = srv_addr;
        dgrams->ss_buf.buf_base = dgrams->slab;
        dgrams->ss_buf.buf_len = sizeof(dgrams->slab);

        ssnetio_on_new_dgram(&clt_addr, &srv_addr, &dgrams->ctx);

        dgram_lookup(dgrams);
    }

BREAK_LABEL:

    return;
}

static void dgram_lookup(DGRAMS *dgrams) {
    uv_loop_t *loop;
    const char* host;
    struct addrinfo hints;
    struct sockaddr *addr;

    /* Maybe it's a ip address in string form */
    if ( 0 == uv_ip4_addr(dgrams->peer.host, dgrams->peer.port, &dgrams->remote.addr4) ||
         0 == uv_ip6_addr(dgrams->peer.host, dgrams->peer.port, &dgrams->remote.addr6)) {

        host = dns_cache_find_host(&dgrams->remote.addr);
        if ( host ) {
            memset(dgrams->peer.host, 0, sizeof(dgrams->peer.host));
            strcpy(dgrams->peer.host, host);
        }

        dgram_read_remote(dgrams);
        dgram_send_remote(dgrams);
    } else {
        /* Lookup dns cache */
        addr = dns_cache_find_ip(dgrams->peer.host, 1);
        if ( !addr )
            addr = dns_cache_find_ip(dgrams->peer.host, 0);

        if ( addr ) {
            cpy_sockaddr(addr, &dgrams->remote.addr);
            set_sockaddr_port(&dgrams->remote.addr, ntohs_u(dgrams->peer.port));

            dgram_read_remote(dgrams);
            dgram_send_remote(dgrams);
        } else {
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            loop = uv_handle_get_loop((uv_handle_t*)dgrams->udp_in);

            if ( 0 != uv_getaddrinfo(loop,
                                     &dgrams->req_dns,
                                     dgram_getaddrinfo_done,
                                     dgrams->peer.host,
                                     NULL,
                                     &hints) ) {
                CHECK(0 == dgram_read_local(dgrams->udp_in));
                dgrams_remove(dgrams);
            }
        }
    }
}

static void dgram_getaddrinfo_done(
    uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    DGRAMS *dgrams;
    struct addrinfo *ai;
    struct addrinfo *ai_ipv4 = NULL;
    struct addrinfo *ai_ipv6 = NULL;

    dgrams = CONTAINER_OF(req, DGRAMS, req_dns);

    if ( 0 == status ) {
        for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
            dns_cache_add(dgrams->peer.host, ai->ai_addr);

            if ( AF_INET == ai->ai_family && !ai_ipv4 ) {
                ai_ipv4 = ai;
            }
            if ( AF_INET6 == ai->ai_family && !ai_ipv6 ) {
                ai_ipv6 = ai;
            }
        }

        cpy_sockaddr(ai_ipv4 ? ai_ipv4->ai_addr : addrs->ai_addr, &dgrams->remote.addr);
        set_sockaddr_port(&dgrams->remote.addr, ntohs_u(dgrams->peer.port));

        dgram_read_remote(dgrams);
        dgram_send_remote(dgrams);
    } else {
        ssnetio_on_msg(
            1,
            "Dgram getaddrinfo failed: %s, domain: %s",
            uv_strerror(status),
            dgrams->peer.host);

        CHECK(0 == dgram_read_local(dgrams->udp_in));
        dgrams_remove(dgrams);
    }

    uv_freeaddrinfo(addrs);
}

static void dgram_send_remote(DGRAMS *dgrams) {
    uv_buf_t buf;
    SSNETIO_BUF *ss_buf;

    ss_buf = uv_handle_get_data((uv_handle_t*)dgrams->udp_in);
    buf = uv_buf_init(ss_buf->data_base, (unsigned int)ss_buf->data_len);

    ssnetio_on_plain_dgram(ss_buf, STREAM_UP, dgrams->ctx);

    if ( 0 == uv_udp_send(
        &dgrams->req_c,
        &dgrams->udp_out,
        &buf,
        1,
        &dgrams->remote.addr,
        dgram_send_done_remote) ) {

        dgram_timer_reset(dgrams);
    } else {
        CHECK(0 == dgram_read_local(dgrams->udp_in));
    }
}

static void dgram_send_done_remote(uv_udp_send_t *req, int status) {
    DGRAMS *dgrams;

    (void)status;

    dgrams = CONTAINER_OF(req, DGRAMS, req_c);
    CHECK(0 == dgram_read_local(dgrams->udp_in));
}

static void dgram_send_local(DGRAMS *dgrams, uv_buf_t *buf) {
    if ( 0 == uv_udp_send(
        &dgrams->req_s,
        dgrams->udp_in,
        buf,
        1,
        &dgrams->local.addr,
        dgram_send_done_local) ) {

        dgram_timer_reset(dgrams);
    } else {
        dgram_read_remote(dgrams);
    }
}

static void dgram_send_done_local(uv_udp_send_t *req, int status) {
    DGRAMS *dgrams;

    (void)status;

    dgrams = CONTAINER_OF(req, DGRAMS, req_s);
    dgram_read_remote(dgrams);
}

static void dgram_read_remote(DGRAMS *dgrams) {
    CHECK(0 == uv_udp_recv_start(
        &dgrams->udp_out,
        dgram_alloc_cb_remote,
        dgram_read_done_remote));
    dgram_timer_reset(dgrams);
}

static void dgram_alloc_cb_remote(
    uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    DGRAMS *dgrams;

    (void)suggested_size;

    dgrams = uv_handle_get_data(handle);
    buf->base = dgrams->ss_buf.buf_base;
    buf->len = MAX_SS_UDP_PAYLOAD_LEN;
}

static void dgram_read_done_remote(
    uv_udp_t *handle, ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    unsigned flags) {

    DGRAMS *dgrams;
    SSNETIO_BUF *ss_buf;
    uv_buf_t buf_s;
    int hdr_len = 0;
    char bs[19];

    (void)flags;
    (void)addr;

    if ( nread <= 0 )
        BREAK_NOW;

    dgrams = CONTAINER_OF(handle, DGRAMS, udp_out);
    ss_buf = &dgrams->ss_buf;
    ASSERT(buf->base == ss_buf->buf_base);

    ss_buf->data_base = ss_buf->buf_base;
    ss_buf->data_len = (size_t)nread;

    ssnetio_on_plain_dgram(ss_buf, STREAM_DOWN, dgrams->ctx);

    /* pack ss hdr */
    if ( dgrams->remote.addr.sa_family == AF_INET ) {
        hdr_len = 7;
        bs[0] = '\1';
        memcpy(&bs[1], &dgrams->remote.addr4.sin_addr, 4);
        memcpy(&bs[5], &dgrams->remote.addr4.sin_port, 2);
    } else if ( dgrams->remote.addr.sa_family == AF_INET6 ) {
        hdr_len = 19;
        bs[0] = '\4';
        memcpy(&bs[1], &dgrams->remote.addr6.sin6_addr, 16);
        memcpy(&bs[17], &dgrams->remote.addr6.sin6_port, 2);
    } else {
        UNREACHABLE();
    }

    /* Insert ss head to the beginning of the buf */
    memmove(ss_buf->buf_base + hdr_len, ss_buf->buf_base, ss_buf->data_len);
    ss_buf->data_len += hdr_len;
    memcpy(ss_buf->buf_base, bs, hdr_len);


    if ( 0 != ssnetio_on_dgram_encrypt(ss_buf, 0) ) {
        ssnetio_on_msg(1, "Encrypt dgram packet failed");
        BREAK_NOW;
    }

    CHECK(0 == uv_udp_recv_stop(handle));

    buf_s = uv_buf_init(ss_buf->data_base, (unsigned int)ss_buf->data_len);
    dgram_send_local(dgrams, &buf_s);

BREAK_LABEL:

    return ;
}

static void dgram_timer_reset(DGRAMS *dgrams) {
    CHECK(0 == uv_timer_start(
        &dgrams->timer,
        dgram_timer_expire,
        srv_ctx.config.idel_timeout,
        0));
}

static void dgram_timer_expire(uv_timer_t *handle) {
    DGRAMS *dgrams;

    dgrams = CONTAINER_OF(handle, DGRAMS, timer);
    ssnetio_on_dgram_teardown(dgrams->ctx);
    dgrams_remove(dgrams);
}
