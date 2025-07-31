/**
 *  Copyright 2025, LeNidViolet.
 *  Created by LeNidViolet on 2025/7/28.
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
#include "internal.h"
#include "dns_cache.h"
#include "dgramsc.h"
#include "shadowsocks-crypto/shadowsocks-crypto.h"

// ==========

extern shadowsocks_crypto_ctx srv_ctx;

static int dgram_read_local(uv_udp_t *handle);


static void dgramsrv_handle_close_done(uv_handle_t* handle) {
    if ( handle ) {
        free(handle);
    }
}

static void dgramsrv_handle_close(uv_udp_t *handle) {
    BUF_RANGE *buf;

    // ReSharper disable once CppDFAConstantConditions
    if ( handle ) {
        buf = uv_handle_get_data((uv_handle_t*)handle);
        if ( buf ) {
            if ( buf->buf_base )
                free(buf->buf_base);
            free(buf);
        }

        uv_udp_recv_stop(handle);
        uv_close((uv_handle_t*)handle, dgramsrv_handle_close_done);
    }
}


/* 启动 dgram 服务 */
int server_dgram_launch(uv_loop_t *loop, const struct sockaddr *addr) {
    uv_udp_t *udp_handle = NULL;
    int ret = -1;
    BUF_RANGE *buf;

    BREAK_ON_NULL(loop);
    BREAK_ON_NULL(addr);


    ENSURE((udp_handle = malloc(sizeof(*udp_handle))) != NULL);
    CHECK(0 == uv_udp_init(loop, udp_handle));

    /* associate buf to handle */
    ENSURE((buf = malloc(sizeof(*buf))) != NULL);
    ENSURE((buf->buf_base = malloc(MAX_SS_UDP_FRAME_LEN)) != NULL);
    buf->data_base   = buf->buf_base;
    buf->buf_len     = MAX_SS_UDP_FRAME_LEN;
    buf->data_len    = 0;
    uv_handle_set_data((uv_handle_t*)udp_handle, buf);

    ret = uv_udp_bind(udp_handle, addr, 0);
    BREAK_ON_FAILURE(ret);

    CHECK(0 == dgram_read_local(udp_handle));

    udp_handle = NULL;

BREAK_LABEL:

    if ( udp_handle ) {
        dgramsrv_handle_close(udp_handle);
    }

    return ret;
}




// ==========
static void dgram_alloc_cb_local(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void dgram_read_done_local(
    uv_udp_t *handle, ssize_t nread,
    const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags);
static void dgram_send_remote(DGRAMS *ds);
static void dgram_send_done_remote(uv_udp_send_t *req, int status);
static void dgram_read_remote(DGRAMS *ds);
static void dgram_alloc_cb_remote(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void dgram_read_done_remote(
    uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
    const struct sockaddr *addr, unsigned flags);
static void dgram_getaddrinfo_done(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);
static void dgram_lookup(DGRAMS *ds);
static void dgram_send_local(DGRAMS *ds, uv_buf_t *buf);
static void dgram_send_done_local(uv_udp_send_t *req, int status);
static void dgram_timer_reset(DGRAMS *ds);
static void dgram_timer_expire(uv_timer_t *handle);



static int dgram_read_local(uv_udp_t *handle) {
    return uv_udp_recv_start(handle, dgram_alloc_cb_local, dgram_read_done_local);
}

static void dgram_alloc_cb_local(
    // ReSharper disable once CppParameterMayBeConstPtrOrRef
    uv_handle_t *handle,
    // ReSharper disable once CppParameterMayBeConst
    size_t suggested_size, uv_buf_t *buf) {
    BUF_RANGE *buf_r;

    (void)suggested_size;

    /* Each listening udp handle has an associated buf for recv data */
    buf_r       = uv_handle_get_data(handle);
    buf->base   = buf_r->buf_base;
    buf->len    = buf_r->buf_len;
}

/* 只通过一个UDP句柄进行监听. 所以通讯联系是一对多的关系
 * 每次有数据到来, 都暂停接收数据直到本次数据发送出去
 */
static void dgram_read_done_local(
    // ReSharper disable once CppParameterMayBeConst
    uv_udp_t *handle, ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    // ReSharper disable once CppParameterMayBeConst
    unsigned flags) {

    BUF_RANGE *buf_r;
    ADDRESS srv_addr = {0};
    ADDRESS clt_addr = {0};
    char key[128];
    DGRAMS *ds;
    uv_loop_t *loop;

    (void)flags;

    if ( nread <= 0 )
        BREAK_NOW;

    buf_r = uv_handle_get_data((uv_handle_t*)handle);
    ASSERT(buf_r->buf_base == buf->base);

    buf_r->data_base    = buf_r->buf_base;
    buf_r->data_len     = (size_t)nread;

    /* decrypt udp data */
    if ( 0 != ssnetio_on_dgram_decrypt(buf_r, 0) ) {
        ssnetio_on_msg(LOG_WARN, "decrypt dgram packet failed");
        BREAK_NOW;
    }
    BREAK_ON_NULL(buf_r->data_len);

    /* obtain address info  srv_addr.domain/port被设置 */
    if ( 0 != s5_parse_addr(buf_r, &srv_addr) ) {
        ssnetio_on_msg(LOG_WARN, "parse dgram packet address failed");
        BREAK_NOW;
    }

    /* Stop recv until all data sent out, or error occur */
    CHECK(0 == uv_udp_recv_stop(handle));

    // clt_addr.domain clt_addr.ip clt_addr.port
    CHECK(0 == sockaddr_to_str(addr, &clt_addr, 1));
    // ip->domain
    strcpy(clt_addr.domain, clt_addr.ip);

    /* unique key */
    snprintf(key, sizeof(key), "%s:%d-%s:%d",
             clt_addr.ip, clt_addr.port,
             srv_addr.domain, srv_addr.port);

    ds = dgrams_find_by_key(key);
    if ( ds ) {
        /* Already in communication */
        dgram_send_remote(ds);
    } else {
        /* Create new one */
        loop = uv_handle_get_loop((uv_handle_t*)handle);

        ds = dgrams_add(key, loop);
        CHECK(NULL != ds);
        ds->udp_in = handle;

        sockaddr_cpy(addr, &ds->local.addr);

        ds->remote_peer     = srv_addr;
        ds->local_peer      = clt_addr;
        ds->ss_buf.buf_base = ds->slab;
        ds->ss_buf.buf_len  = sizeof(ds->slab);

        dgram_lookup(ds);
    }

BREAK_LABEL:

    return;
}

static void dgram_lookup(DGRAMS *ds) {
    uv_loop_t *loop;
    const char* host;
    struct addrinfo hints;
    struct sockaddr *addr;

    /* Maybe it's an ip address in string form */
    if ( 0 == uv_ip4_addr(ds->remote_peer.domain, ds->remote_peer.port, &ds->remote.addr4) ||
         0 == uv_ip6_addr(ds->remote_peer.domain, ds->remote_peer.port, &ds->remote.addr6) ) {

        // remote_peer.ip
        strcpy(ds->remote_peer.ip, ds->remote_peer.domain);

        /* 替换成可读性更高的域名 */
        host = dns_cache_find_host(&ds->remote.addr);
        if ( host ) {
            memset(ds->remote_peer.domain, 0, sizeof(ds->remote_peer.domain));
            strcpy(ds->remote_peer.domain, host);
        }

        ssnetio_on_new_dgram(&ds->local_peer, &ds->remote_peer, &ds->ctx);

        dgram_read_remote(ds);
        dgram_send_remote(ds);
    } else {
        /* Lookup dns cache */
        addr = dns_cache_find_ip(ds->remote_peer.domain, 1);
        if ( !addr )
            addr = dns_cache_find_ip(ds->remote_peer.domain, 0);

        if ( addr ) {
            sockaddr_cpy(addr, &ds->remote.addr);
            sockaddr_set_port(&ds->remote.addr, ds->remote_peer.port);

            // remote_peer.ip
            sockaddr_to_str(addr, &ds->remote_peer, 0);
            ssnetio_on_new_dgram(&ds->local_peer, &ds->remote_peer, &ds->ctx);

            dgram_read_remote(ds);
            dgram_send_remote(ds);
        } else {
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            loop = uv_handle_get_loop((uv_handle_t*)ds->udp_in);

            if ( 0 != uv_getaddrinfo(loop,
                                     &ds->req_dns,
                                     dgram_getaddrinfo_done,
                                     ds->remote_peer.domain,
                                     NULL,
                                     &hints) ) {
                CHECK(0 == dgram_read_local(ds->udp_in));
                dgrams_remove(ds);
            }
        }
    }
}

static void dgram_getaddrinfo_done(
    // ReSharper disable once CppParameterMayBeConst
    uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    DGRAMS *ds;
    struct addrinfo *ai;
    struct addrinfo *ai_ipv4 = NULL;
    struct addrinfo *ai_ipv6 = NULL;

    ds = CONTAINER_OF(req, DGRAMS, req_dns);

    if ( 0 == status ) {
        for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
            dns_cache_add(ds->remote_peer.domain, ai->ai_addr);

            if ( AF_INET == ai->ai_family && !ai_ipv4 ) {
                ai_ipv4 = ai;
            }
            if ( AF_INET6 == ai->ai_family && !ai_ipv6 ) {
                ai_ipv6 = ai;
            }
        }

        sockaddr_cpy(ai_ipv4 ? ai_ipv4->ai_addr : addrs->ai_addr, &ds->remote.addr);
        sockaddr_set_port(&ds->remote.addr, ds->remote_peer.port);

        sockaddr_to_str(&ds->remote.addr, &ds->remote_peer, 0);
        ssnetio_on_new_dgram(&ds->local_peer, &ds->remote_peer, &ds->ctx);

        dgram_read_remote(ds);
        dgram_send_remote(ds);
    } else {
        ssnetio_on_msg(
            LOG_WARN,
            "dgram getaddrinfo failed: %s, domain: %s",
            uv_strerror(status),
            ds->remote_peer.domain);

        CHECK(0 == dgram_read_local(ds->udp_in));
        dgrams_remove(ds);
    }

    uv_freeaddrinfo(addrs);
}

static void dgram_send_remote(DGRAMS *ds) {
    uv_buf_t buf_t;
    BUF_RANGE *buf;

    buf = uv_handle_get_data((uv_handle_t*)ds->udp_in);
    buf_t = uv_buf_init(buf->data_base, (unsigned int)buf->data_len);

    ssnetio_on_plain_dgram(buf, STREAM_UP, ds->ctx);

    if ( 0 == uv_udp_send(
        &ds->req_c,
        &ds->udp_out,
        &buf_t,
        1,
        &ds->remote.addr,
        dgram_send_done_remote) ) {

        dgram_timer_reset(ds);
    } else {
        CHECK(0 == dgram_read_local(ds->udp_in));
        dgrams_remove(ds);
    }
}

// ReSharper disable once CppParameterMayBeConst
static void dgram_send_done_remote(uv_udp_send_t *req, int status) {
    DGRAMS *ds;

    (void)status;

    ds = CONTAINER_OF(req, DGRAMS, req_c);
    CHECK(0 == dgram_read_local(ds->udp_in));
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
static void dgram_send_local(DGRAMS *ds, uv_buf_t *buf) {
    if ( 0 == uv_udp_send(
        &ds->req_s,
        ds->udp_in,
        buf,
        1,
        &ds->local.addr,
        dgram_send_done_local) ) {

        dgram_timer_reset(ds);
    } else {
        dgram_read_remote(ds);
    }
}

// ReSharper disable once CppParameterMayBeConst
static void dgram_send_done_local(uv_udp_send_t *req, int status) {
    DGRAMS *ds;

    (void)status;

    ds = CONTAINER_OF(req, DGRAMS, req_s);
    dgram_read_remote(ds);
}

static void dgram_read_remote(DGRAMS *ds) {
    CHECK(0 == uv_udp_recv_start(
        &ds->udp_out,
        dgram_alloc_cb_remote,
        dgram_read_done_remote));
    dgram_timer_reset(ds);
}

static void dgram_alloc_cb_remote(
    // ReSharper disable once CppParameterMayBeConstPtrOrRef
    uv_handle_t *handle,
    // ReSharper disable once CppParameterMayBeConst
    size_t suggested_size, uv_buf_t *buf) {
    DGRAMS *ds;

    (void)suggested_size;

    ds = uv_handle_get_data(handle);
    buf->base   = ds->ss_buf.buf_base;
    buf->len    = MAX_SS_UDP_PAYLOAD_LEN;
}

static void dgram_read_done_remote(
    // ReSharper disable once CppParameterMayBeConst
    uv_udp_t *handle, ssize_t nread,
    const uv_buf_t *buf,
    const struct sockaddr *addr,
    // ReSharper disable once CppParameterMayBeConst
    unsigned flags) {

    DGRAMS *ds;
    BUF_RANGE *buf_r;
    uv_buf_t buf_t;
    int hdr_len = 0;
    char bs[19];

    (void)flags;
    (void)addr;

    if ( nread <= 0 )
        BREAK_NOW;

    ds = CONTAINER_OF(handle, DGRAMS, udp_out);
    buf_r = &ds->ss_buf;
    ASSERT(buf->base == buf_r->buf_base);

    buf_r->data_base    = buf_r->buf_base;
    buf_r->data_len     = (size_t)nread;

    ssnetio_on_plain_dgram(buf_r, STREAM_DOWN, ds->ctx);

    /* pack ss hdr */
    if ( ds->remote.addr.sa_family == AF_INET ) {
        hdr_len = 7;
        bs[0] = '\1';
        memcpy(&bs[1], &ds->remote.addr4.sin_addr, 4);
        memcpy(&bs[5], &ds->remote.addr4.sin_port, 2);
    } else if ( ds->remote.addr.sa_family == AF_INET6 ) {
        hdr_len = 19;
        bs[0] = '\4';
        memcpy(&bs[1], &ds->remote.addr6.sin6_addr, 16);
        memcpy(&bs[17], &ds->remote.addr6.sin6_port, 2);
    } else {
        UNREACHABLE();
    }

    /* Insert ss head to the beginning of the buf */
    memmove(buf_r->buf_base + hdr_len, buf_r->buf_base, buf_r->data_len);
    buf_r->data_len += hdr_len;
    memcpy(buf_r->buf_base, bs, hdr_len);


    if ( 0 != ssnetio_on_dgram_encrypt(buf_r, 0) ) {
        ssnetio_on_msg(LOG_WARN, "encrypt dgram packet failed");
        BREAK_NOW;
    }

    /* 发送完成之前停止接收 */
    CHECK(0 == uv_udp_recv_stop(handle));

    buf_t = uv_buf_init(buf_r->data_base, (unsigned int)buf_r->data_len);
    dgram_send_local(ds, &buf_t);

BREAK_LABEL:

    return ;
}

static void dgram_timer_reset(DGRAMS *ds) {
    CHECK(0 == uv_timer_start(
        &ds->timer,
        dgram_timer_expire,
        srv_ctx.config.idel_timeout,
        0));
}

static void dgram_timer_expire(uv_timer_t *handle) {
    DGRAMS *ds;

    ds = CONTAINER_OF(handle, DGRAMS, timer);
    ssnetio_on_dgram_teardown(ds->ctx);
    dgrams_remove(ds);
}
