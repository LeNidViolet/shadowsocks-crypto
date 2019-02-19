/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/7/31.
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

#include <stdlib.h>
#include "shadowsocks-crypto/shadowsocks-crypto.h"
#include "internal.h"
#include "dgramsc.h"
#include "dnsc.h"
#include "s5.h"

SSNETIO_CTX clt_ctx;
static union {
    struct sockaddr addr;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
} ss_srv;

static int dgramc_outstanding = 0;

static int client_run(SSNETIO_CTX *ctx);
static void get_ss_srv_addr_done(
    uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);
static int do_handshake(PROXY_NODE *pn);
static int do_req_start(PROXY_NODE *pn);
static int do_req_parse(PROXY_NODE *pn);
static int do_req_connect_start(PROXY_NODE *pn);
static int do_req_connect(PROXY_NODE *pn);
static int do_proxy_ready(PROXY_NODE *pn);
static int do_dgram_start(PROXY_NODE *pn);
static int do_dgram_stop(PROXY_NODE *pn);
static int do_dgram_response(PROXY_NODE *pn);

static void dgram_read(DGRAMC *dgramc);
static void dgram_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void dgram_read_done(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
    const struct sockaddr *addr, unsigned flags);
static void dgram_read_done_l(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
    const struct sockaddr *addr, unsigned flags);
static void dgram_read_done_r(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
    const struct sockaddr *addr, unsigned flags);
static void dgram_write(DGRAMC *dgramc, const void *data, unsigned int len);
static void dgram_write_done(uv_udp_send_t* req, int status);
static void dgram_timer_reset(DGRAMC *dgramc);
static void dgram_timer_expire(uv_timer_t *handle);
static void dgram_tear_down(DGRAMC_NODE *dcn);
static void dgram_close_done(uv_handle_t* handle);


int ssnetio_client_launch(SSNETIO_CTX *ctx) {
    int ret = -1;

    BREAK_ON_NULL(ctx);
    BREAK_ON_NULL(ctx->config.bind_host);
    BREAK_ON_NULL(ctx->config.bind_port);
    BREAK_ON_NULL(ctx->config.idel_timeout);
    BREAK_ON_NULL(ctx->config.ss_srv_addr);
    BREAK_ON_NULL(ctx->config.ss_srv_port);

    runas(client_side);

    memcpy(&clt_ctx, ctx, sizeof(clt_ctx));

    ret = client_run(&clt_ctx);

BREAK_LABEL:

    return ret;
}

static int client_run(SSNETIO_CTX *ctx) {
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
                         get_ss_srv_addr_done,  /* got ss server address first */
                         ctx->config.ss_srv_addr,
                         NULL,
                         &hints);
    if ( 0 != ret ) {
        ssnetio_on_msg(1, "uv_getaddrinfo failed: %s", uv_strerror(ret));
        BREAK_NOW;
    }

    ret = uv_run(loop, UV_RUN_DEFAULT);

    uv_loop_close(loop);

BREAK_LABEL:

    return ret;
}

static void get_ss_srv_addr_done(
    uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    uv_loop_t *loop;
    static uv_getaddrinfo_t bind_req;
    struct addrinfo hints;
    int ret;
    ADDRESS address = {0};

    if ( status < 0 ) {
        ssnetio_on_msg(1, "uv_getaddrinfo failed: %s", uv_strerror(status));
        BREAK_NOW;
    }

    /* 获取SS服务器地址,端口 */
    if ( addrs->ai_family == AF_INET ) {
        ss_srv.addr4 = *(const struct sockaddr_in *)addrs->ai_addr;
        ss_srv.addr4.sin_port = htons_u(clt_ctx.config.ss_srv_port);
    }
    else if ( addrs->ai_family == AF_INET6 ) {
        ss_srv.addr6 = *(const struct sockaddr_in6 *)addrs->ai_addr;
        ss_srv.addr6.sin6_port = htons_u(clt_ctx.config.ss_srv_port);
    }
    else {
        UNREACHABLE();
    }


    CHECK(0 == str_sockaddr(&ss_srv.addr, &address));
    ssnetio_on_msg(3, "shadowsocks server %s:%d", address.host, address.port);

    loop = uv_req_get_data((uv_req_t *)req);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    uv_req_set_data((uv_req_t *)&bind_req, loop);

    ret = uv_getaddrinfo(loop,
                         &bind_req,
                         do_bind,
                         clt_ctx.config.bind_host,
                         NULL,
                         &hints);
    if ( 0 != ret ) {
        ssnetio_on_msg(1, "uv_getaddrinfo failed: %s", uv_strerror(ret));
    }

BREAK_LABEL:

    if ( addrs )
        uv_freeaddrinfo(addrs);
}

void conn_timer_expire_client(uv_timer_t *handle) {
    CONN *conn;
    CONN *incoming;
    CONN *outgoing;

    conn = CONTAINER_OF(handle, CONN, timer_handle);

    incoming = &conn->pn->incoming;
    outgoing = &conn->pn->outgoing;

    switch ( conn->pn->state ) {
    case s_handshake:
    case s_req_start:
    case s_req_parse:
    case s_proxy_ready:
    case s_dgram_start:
    case s_dgram_stop:
        ASSERT(conn == incoming);
        incoming->result = UV_ETIMEDOUT;
        break;
    case s_req_connect:
    case s_proxy_start:
        outgoing->result = UV_ETIMEDOUT;
        break;
    case s_req_lookup:
        UNREACHABLE();
        break;
    default:
        conn->result = UV_ETIMEDOUT;  /* s_proxy, .. */
        break;
    }
    do_next_client(conn);
}

void do_next_client(CONN *sender) {
    PROXY_NODE *pn;
    int new_state = s_max;

    pn = sender->pn;

    ASSERT(pn->state != s_dead);
    switch (pn->state) {
    case s_handshake:
        new_state = do_handshake(pn);
        break;
    case s_req_start:
        new_state = do_req_start(pn);
        break;
    case s_req_parse:
        new_state = do_req_parse(pn);
        break;
    case s_req_connect:
        new_state = do_req_connect(pn);
        break;
    case s_dgram_start:
        new_state = do_dgram_start(pn);
        break;
    case s_dgram_stop:
        new_state = do_dgram_stop(pn);
        break;
    case s_proxy_ready:
        new_state = do_proxy_ready(pn);
        break;
    case s_proxy_start:
        new_state = do_proxy_start(pn);
        break;
    case s_proxy:
        new_state = do_proxy(sender);
        break;
    case s_req_lookup:
        UNREACHABLE();
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

static int do_handshake(PROXY_NODE *pn) {
    CONN *incoming;
    int new_state = s_max, err;

    incoming = &pn->incoming;

    if ( incoming->result < 0 ) {
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_done);
    ASSERT(incoming->wrstate == c_stop);
    incoming->rdstate = c_stop;

    err = s5_simple_check(incoming->ss_buf.buf_base, (size_t)incoming->result);
    switch ( err ) {
    case s5_invalid_version:
    case s5_invalid_length:
        new_state = do_kill(pn);
        break;
    case s5_invalid_method:
        conn_write(incoming, "\5\255", 2);  /* No acceptable auth. */
        new_state = s_kill;
        break;
    case 0:
        conn_write(incoming, "\5\0", 2);  /* No auth required. */
        new_state = s_req_start;
        break;
    default:
        UNREACHABLE();
        break;
    }

BREAK_LABEL:

    return new_state;
}

static int do_req_start(PROXY_NODE *pn) {
    CONN *incoming;
    int new_state;

    incoming = &pn->incoming;

    if ( incoming->result < 0 ) {
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_done);
    incoming->wrstate = c_stop;

    conn_read(incoming);

    new_state = s_req_parse;

BREAK_LABEL:

    return new_state;
}


static int do_req_parse(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int new_state, cmd;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( incoming->result < 8 ) {  /* |VER|CMD|RSV|ATYP|DST.ADDR|DST.PORT|DATA */
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_done);
    ASSERT(incoming->wrstate == c_stop);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);
    incoming->rdstate = c_stop;

    cmd = incoming->ss_buf.buf_base[1];

    if ( s5_cmd_bind == cmd ) {
        /* Not supported */
        ssnetio_on_msg(1, "%4d BIND requests are not supported.", pn->index);
        new_state = do_kill(pn);
        BREAK_NOW;
    }
    if ( s5_cmd_udp_associate == cmd ) {
        new_state = do_dgram_response(pn);
        BREAK_NOW;
    }
    if ( s5_cmd_connect != cmd ) {
        ssnetio_on_msg(1, "%4d Unknow s5 command %d.", pn->index, cmd);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    /* Save data length */
    incoming->ss_buf.data_len = (size_t)incoming->result;

    new_state = do_req_connect_start(pn);

BREAK_LABEL:

    return new_state;
}

static int do_req_connect_start(PROXY_NODE *pn) {
    int new_state;
    CONN *incoming;
    CONN *outgoing;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;
    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_stop);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);

    /* Just connect to ss server */
    if ( 0 != uv_tcp_connect(&outgoing->t.connect_req,
                             &outgoing->handle.tcp,
                             &ss_srv.addr,
                             conn_connect_done) ) {
        new_state = do_kill(pn);
        BREAK_NOW;
    }
    conn_timer_reset(outgoing);
    pn->outstanding++;

    new_state = s_req_connect;

BREAK_LABEL:

    return new_state;
}


static int do_req_connect(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int new_state;
    int addrlen;
    char addr_storage[sizeof(struct sockaddr_in6)];
    static char ipv4_reply[] = { "\5\0\0\1\0\0\0\0\16\16" };
    static char ipv6_reply[] = { "\5\0\0\4"
                                 "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                 "\10\10" };

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( 0 != outgoing->result ) {
        ssnetio_on_msg(
            1,
            "%4d Connect to shadowsocks server failed: %s",
            pn->index,
            uv_strerror((int)outgoing->result));
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_stop);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);

    str_sockaddr(&ss_srv.addr, &outgoing->peer);
    ssnetio_on_connection_made(pn);

    snprintf(pn->link_info, sizeof(pn->link_info), "%s:%d -> %s:%d",
             incoming->peer.host,
             incoming->peer.port,
             outgoing->peer.host,
             outgoing->peer.port);

    addrlen = sizeof(addr_storage);
    if ( 0 != uv_tcp_getsockname(&outgoing->handle.tcp,
                                 (struct sockaddr*)addr_storage,
                                 &addrlen) ) {
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    if ( addrlen == sizeof(struct sockaddr_in) ) {
        conn_write(incoming, ipv4_reply, 10);
    } else if ( addrlen == sizeof(struct sockaddr_in6) ) {
        conn_write(incoming, ipv6_reply, 22);
    } else {
        UNREACHABLE();
    }

    new_state = s_proxy_ready;

BREAK_LABEL:

    return new_state;
}


static int do_proxy_ready(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int new_state;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( incoming->result < 0 ) {
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_done);
    ASSERT(outgoing->rdstate == c_stop);
    ASSERT(outgoing->wrstate == c_stop);
    incoming->wrstate = c_stop;

    /* Restore data length */
    incoming->result = incoming->ss_buf.data_len;
    /* Advance data pointer */
    if ( 0 != ssnetio_on_stream_encrypt(incoming, 3) ) {
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    /* Tell ss server to make a connection. */
    conn_write(
        outgoing,
        incoming->ss_buf.data_base,
        (unsigned int)incoming->ss_buf.data_len);

    new_state = s_proxy_start;

BREAK_LABEL:

    return new_state;
}

static int do_dgram_start(PROXY_NODE *pn) {
    CONN *incoming;
    int ret;

    incoming = &pn->incoming;

    if ( incoming->result < 0 ) {
        ret = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(incoming->rdstate == c_stop);
    ASSERT(incoming->wrstate == c_done);
    incoming->wrstate = c_stop;

    /* Wait EOF */
    conn_read(incoming);

    ret = s_dgram_stop;

BREAK_LABEL:

    return ret;
}

static int do_dgram_stop(PROXY_NODE *pn) {
    CONN *incoming;

    incoming = &pn->incoming;

    ASSERT(incoming->wrstate == c_stop);
    incoming->rdstate = c_stop;

    /* It should be EOF or read error or timer expire */
    ASSERT(incoming->result < 0);

    return do_kill(pn);
}

static int do_dgram_response(PROXY_NODE *pn) {
    int ret;
    CONN *conn;
    DGRAMC_NODE *dcn;
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } s;
    int addr_len;
    void *p_addr;
    unsigned short port;
    char *p;

    conn = &pn->incoming;
    ENSURE((dcn = malloc(sizeof(*dcn))) != NULL);
    memset(dcn, 0, sizeof(*dcn));
    CHECK(0 == uv_udp_init(pn->loop, &dcn->incoming.handle.udp));
    CHECK(0 == uv_udp_init(pn->loop, &dcn->outgoing.handle.udp));
    CHECK(0 == uv_timer_init(pn->loop, &dcn->timer));
    uv_handle_set_data(&dcn->incoming.handle.handle, &dcn->incoming);
    uv_handle_set_data(&dcn->outgoing.handle.handle, &dcn->outgoing);
    uv_handle_set_data((uv_handle_t*)&dcn->timer, &dcn->incoming);
    dcn->tcp = conn;
    dcn->incoming.dcn = dcn;
    dcn->outgoing.dcn = dcn;
    dcn->incoming.ss_buf.buf_base = dcn->incoming.slab;
    dcn->incoming.ss_buf.buf_len = sizeof(dcn->incoming.slab);
    dcn->outgoing.ss_buf.buf_base = dcn->outgoing.slab;
    dcn->outgoing.ss_buf.buf_len = sizeof(dcn->outgoing.slab);
    dcn->state = u_using;
    cpy_sockaddr(&ss_srv.addr, &dcn->outgoing.addr.addr);

    memset(&s, 0, sizeof(s));
    addr_len = sizeof(s);
    CHECK(0 == uv_tcp_getsockname(
        &conn->handle.tcp,
        (struct sockaddr *)&s,
        &addr_len));

    if ( s.addr.sa_family == AF_INET ) s.addr4.sin_port = 0;
    if ( s.addr.sa_family == AF_INET6 ) s.addr6.sin6_port = 0;

    /* Random choice a port */
    CHECK(0 == uv_udp_bind(&dcn->incoming.handle.udp, &s.addr, 0));
    addr_len = sizeof(s);
    CHECK(0 == uv_udp_getsockname(
        &dcn->incoming.handle.udp,
        (struct sockaddr *)&s,
        &addr_len));
    p_addr = s.addr.sa_family ==
        AF_INET ? (void*)&s.addr4.sin_addr : (void*)&s.addr6.sin6_addr;
    addr_len = s.addr.sa_family ==
        AF_INET ? sizeof(s.addr4.sin_addr) : sizeof(s.addr6.sin6_addr);
    port = s.addr.sa_family ==
        AF_INET6 ? s.addr4.sin_port : s.addr6.sin6_port;

    /* Tell socks5 app udp address */
    /* struct s5 pkt */
    p = conn->ss_buf.buf_base;
    *p++ = (char)'\5';
    *p++ = (char)'\0';
    *p++ = (char)'\0';
    *p++ = s.addr.sa_family == AF_INET ? (char)'\1' : (char)'\4';

    memcpy(p, p_addr, addr_len);
    p += addr_len;

    memcpy(p, &port, sizeof(port));
    p += sizeof(port);

    conn_write(conn, conn->ss_buf.buf_base, (unsigned int)(p - conn->ss_buf.buf_base));
    dgram_read(&dcn->incoming);
    dgram_read(&dcn->outgoing);

    ret = s_dgram_start;

    dgramc_outstanding++;
BREAK_LABEL:

    return ret;
}

static void dgram_read(DGRAMC *dgramc) {
    if ( 0 != uv_udp_recv_start(
        &dgramc->handle.udp,
        dgram_alloc_cb,
        dgram_read_done) ) {

        dgram_tear_down(dgramc->dcn);
    } else {
        dgram_timer_reset(dgramc);
        conn_timer_reset(dgramc->dcn->tcp);
    }
}

static void dgram_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    DGRAMC *dgramc;

    (void)suggested_size;

    dgramc = uv_handle_get_data(handle);
    buf->base = dgramc->ss_buf.buf_base;
    if ( dgramc == &dgramc->dcn->incoming ) {
        buf->len = MAX_SS_UDP_PAYLOAD_LEN + MAX_S5_HDR_LEN;
    } else {
        buf->len = dgramc->ss_buf.buf_len;
    }
}

static void dgram_read_done(
    uv_udp_t *handle,
    ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    unsigned flags) {

    int is_local;
    DGRAMC *dgramc;
    dgramc = uv_handle_get_data((uv_handle_t*)handle);

    is_local = dgramc == &dgramc->dcn->incoming;
    if ( is_local ) {
        dgram_read_done_l(handle, nread, buf, addr, flags);
    } else {
        dgram_read_done_r(handle, nread, buf, addr, flags);
    }
}

static void dgram_read_done_l(
    uv_udp_t *handle,
    ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    unsigned flags) {
    DGRAMC *incoming;
    SSNETIO_BUF *ss_buf;
    ADDRESS local = {0};
    ADDRESS remote = {0};

    (void)flags;

    if ( nread <= 0 )
        BREAK_NOW;

    /* NOT support frag */
    if ( buf->base[2] != '\0' ) {
        ssnetio_on_msg(1, "Ignore frag dgram packet");
        BREAK_NOW;
    }

    incoming = uv_handle_get_data((uv_handle_t*)handle);
    ss_buf = &incoming->ss_buf;
    ASSERT(ss_buf->buf_base == buf->base);

    if ( nread > ss_buf->buf_len - MAX_SS_UDP_WRAPPER_LEN ) {
        ssnetio_on_msg(1, "Ignore too large dgram packet(local): %d", nread);
        BREAK_NOW;
    }

    ss_buf->data_base = ss_buf->buf_base;
    ss_buf->data_len = (size_t)nread;

    /* Emit dgram session */
    if ( 0 == incoming->addr.addr.sa_family ) {
        cpy_sockaddr(addr, &incoming->addr.addr);

        str_sockaddr(addr, &local);
        str_sockaddr(&ss_srv.addr, &remote);
        ssnetio_on_new_dgram(&local, &remote, &incoming->dcn->ctx);
    }
    /* Assume that will no DGRAM from different address */
    ASSERT(0 == equal_sockaddr(addr, &incoming->addr.addr));

    /* Advance offset */
    if ( 0 != ssnetio_on_dgram_encrypt(ss_buf, 3) ) {
        ssnetio_on_msg(1, "Encrypt dgram packet failed");
        BREAK_NOW;
    }

    uv_udp_recv_stop(&incoming->handle.udp);
    dgram_write(
        &incoming->dcn->outgoing,
        ss_buf->data_base,
        (unsigned int)ss_buf->data_len);

BREAK_LABEL:

    return;
}

static void dgram_read_done_r(
    uv_udp_t *handle,
    ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    unsigned flags) {
    DGRAMC *outgoing;
    SSNETIO_BUF *ss_buf;

    (void)flags;
    (void)addr;

    if ( nread <= 0 )
        BREAK_NOW;

    outgoing = uv_handle_get_data((uv_handle_t*)handle);
    ss_buf = &outgoing->ss_buf;
    ASSERT(ss_buf->buf_base == buf->base);

    if ( nread > ss_buf->buf_len - 3 ){
        ssnetio_on_msg(1, "Ignore too large dgram packet(remote): %d", nread);
        BREAK_NOW;
    }

    ss_buf->data_base = ss_buf->buf_base;
    ss_buf->data_len = (size_t)nread;

    if ( 0 != ssnetio_on_dgram_decrypt(ss_buf, 0) ){
        ssnetio_on_msg(1, "Decrypt dgram packet failed");
        BREAK_NOW;
    }

    /* Add socks5 hdr */
    memmove(ss_buf->buf_base + 3, ss_buf->data_base, ss_buf->data_len);
    memset(ss_buf->buf_base, 0, 3);
    ss_buf->data_len += 3;

    uv_udp_recv_stop(&outgoing->handle.udp);
    dgram_write(
        &outgoing->dcn->incoming,
        ss_buf->buf_base,
        (unsigned int)ss_buf->data_len);

BREAK_LABEL:

    return;
}

static void dgram_write(DGRAMC *dgramc, const void *data, unsigned int len) {
    uv_buf_t buf;
    buf = uv_buf_init((char*)data, len);

    if ( 0 != uv_udp_send(
        &dgramc->req,
        &dgramc->handle.udp,
        &buf,
        1,
        &dgramc->addr.addr,
        dgram_write_done) ) {
        dgram_tear_down(dgramc->dcn);
    } else {
        dgram_timer_reset(dgramc);
        conn_timer_reset(dgramc->dcn->tcp);
    }
}

static void dgram_write_done(uv_udp_send_t* req, int status) {
    DGRAMC *dgramc, *p;

    (void)status;

    dgramc = CONTAINER_OF(req, DGRAMC, req);
    p = dgramc == &dgramc->dcn->incoming ? &dgramc->dcn->outgoing : &dgramc->dcn->incoming;
    dgram_read(p);
}

static void dgram_timer_reset(DGRAMC *dgramc) {
    CHECK(0 == uv_timer_start(
        &dgramc->dcn->timer,
        dgram_timer_expire,
        clt_ctx.config.idel_timeout,
        0));
}

static void dgram_timer_expire(uv_timer_t *handle) {
    DGRAMC *dgramc;

    dgramc = uv_handle_get_data((uv_handle_t*)handle);
    dgram_tear_down(dgramc->dcn);
}

static void dgram_tear_down(DGRAMC_NODE *dcn) {
    if ( dcn->state < u_closing0 ) {
        dcn->state = u_closing0;
        uv_close(&dcn->incoming.handle.handle, dgram_close_done);
        uv_close(&dcn->outgoing.handle.handle, dgram_close_done);
        uv_close((uv_handle_t*)&dcn->timer, dgram_close_done);
    }
}

static void dgram_close_done(uv_handle_t* handle) {
    DGRAMC *dgramc;
    DGRAMC_NODE *dcn;

    dgramc = uv_handle_get_data(handle);
    dcn = dgramc->dcn;

    dcn->state++;
    if ( u_dead == dcn->state ) {
        ssnetio_on_dgram_teardown(dcn->ctx);

        if ( DEBUG_CHECKS )
            memset(dcn, 0xff, sizeof(*dcn));
        free(dcn);

        dgramc_outstanding--;
    }
}
