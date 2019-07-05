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


// ==========
sscrypto_ctx srv_ctx;

static int server_run(sscrypto_ctx *ctx);
static void do_bind(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);

/* LAUNCHER */
int ssnetio_server_launch(const sscrypto_ctx *ctx) {
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

/* 取得NETIO底层操作接口 */
void ssnetio_server_port(ioctl_port *port) {
    port->write_stream_out = ssnetio_write_stream_out;
    port->stream_pause = ssnetio_stream_pause;
}


static void server_stop(void) {
    server_dns_stop();
    server_dgram_stop();
    server_tcp_stop();
    uv_stop(uv_default_loop());
}

static void async_cb(uv_async_t* handle) {
    (void)handle;

    server_stop();
}

void ssnetio_server_stop(void) {
    static uv_async_t uvasync;

    /* 利用 async_t 在 loop 所在线程中去关闭 loop */
    uv_async_init(uv_default_loop(), &uvasync, async_cb);
    uv_async_send(&uvasync);
}

static int server_run(sscrypto_ctx *ctx) {
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
        ssnetio_on_msg(ERROR, "uv_getaddrinfo failed: %s", uv_strerror(ret));
        BREAK_NOW;
    }

    /* Start the event loop.  Control continues in do_bind(). */
    ret = uv_run(loop, UV_RUN_DEFAULT);

    uv_loop_close(loop);

BREAK_LABEL:

    return ret;
}


static void do_bind(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    address address = {0};
    unsigned int naddrs;
    struct addrinfo *ai;
    uv_loop_t *loop;
    int ret = -1;
    union {
        struct sockaddr addr;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } s;
    const unsigned short dns_port = 53;

    loop = uv_req_get_data((uv_req_t *)req);

    if ( status < 0 ) {
        ssnetio_on_msg(ERROR, "uv_getaddrinfo failed: %s", uv_strerror(status));
        BREAK_NOW;
    }

    /* Just bind to ipv4 ipv6 address */
    naddrs = 0;
    for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
        if ( AF_INET == ai->ai_family  || AF_INET6 == ai->ai_family ) {
            naddrs++;
        }
    }
    BREAK_ON_NULL(naddrs);

    for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
        if ( AF_INET != ai->ai_family && AF_INET6 != ai->ai_family ) {
            continue;
        }

        // 组合地址
        sockaddr_cpy(ai->ai_addr, &s.addr);
        sockaddr_set_port(&s.addr, srv_ctx.config.bind_port);

        CHECK(0 == sockaddr_to_str(&s.addr, &address));

        /* tcp bind */
        ret = server_tcp_launch(loop, &s.addr);
        if ( 0 != ret ) {
            ssnetio_on_msg(
                FATAL,
                "tcp server launch failed: %s [%s:%d]",
                uv_strerror(ret),
                address.host,
                address.port);
            BREAK_NOW;
        }

        /* udp bind */
        ret = server_dgram_launch(loop, &s.addr);
        if ( 0 != ret ) {
            ssnetio_on_msg(
                FATAL,
                "dgram server launch failed: %s [%s:%d]",
                uv_strerror(ret),
                address.host,
                address.port);
            BREAK_NOW;
        }

        /* dns bind */
        sockaddr_set_port(&s.addr, dns_port);
        ret = server_dns_launch(loop, &s.addr);
        if ( 0 != ret ) {
            ssnetio_on_msg(
                FATAL,
                "dns server launch failed: %s [%s:%d]",
                uv_strerror(ret),
                address.host,
                dns_port);
            BREAK_NOW;
        }

        ssnetio_on_bind(address.host, address.port);
    }

BREAK_LABEL:

    if ( addrs )
        uv_freeaddrinfo(addrs);

    if ( 0 != ret ) {
        server_stop();
    }
}

