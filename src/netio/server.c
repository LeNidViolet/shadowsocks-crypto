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

#include "uv.h"
#include "shadowsocks-crypto/shadowsocks-crypto.h"
#include "internal.h"
#include "dgramsc.h"
#include "dns_cache.h"


// ==========
sscrypto_ctx srv_ctx;

static int server_run(sscrypto_ctx *ctx);
static void server_handle_walk_callback(uv_handle_t* Handle, void* arg);
static void server_exit_async_cb(uv_async_t* handle);

union {
    uv_handle_t             handle;
    uv_async_t              async;
} exit_async;         // 可以在任意线程调用, 但是必须在loop所在线程初始化


/* LAUNCHER */
int ssnetio_server_launch(const sscrypto_ctx *ctx) {
    int ret = -1;

    BREAK_ON_NULL(ctx);
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

static int server_run(sscrypto_ctx *ctx) {
    uv_loop_t                   *loop;
    int                         ret;

    union {
        uv_handle_t             handle;
        uv_tcp_t                tcp;
        uv_stream_t             stream;
    } tcpv4;                                            // TCPv4 listening socket

    union {
        uv_handle_t             handle;
        uv_tcp_t                tcp;
        uv_stream_t             stream;
    } tcpv6;                                            // TCPv6 listening socket

    union {
        uv_handle_t             handle;
        uv_udp_t                udp;
    } udpv4;                                            // UDPv4 listening socket

    union {
        uv_handle_t             handle;
        uv_udp_t                udp;
    } udpv6;                                            // UDPv6 listening socket

    // Union to hold sockaddr structures (supports both IPv4 and IPv6)
    union {
        struct sockaddr addr;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } addr = {};
    const char *addrs;
    const char *addrsv6;
    bool success = false;

    loop = uv_default_loop();

    ret = uv_tcp_init(loop, &tcpv4.tcp);
    CHECK(0 == ret);
    ret = uv_tcp_init(loop, &tcpv6.tcp);
    CHECK(0 == ret);
    ret = uv_udp_init(loop, &udpv4.udp);
    CHECK(0 == ret);
    ret = uv_udp_init(loop, &udpv6.udp);
    CHECK(0 == ret);

    // LISTEN ON TCPv4
    addrs = "0.0.0.0";
    ret = uv_ip4_addr(addrs, ctx->config.bind_port, &addr.addr4);
    CHECK(0 == ret);
    ret = server_tcp_launch(loop, &addr.addr);
    BREAK_ON_FALSE(0 == ret);

    // LISTEN ON UDPv4
    ret = server_dgram_launch(loop, &addr.addr);
    BREAK_ON_FALSE(0 == ret);


    // LISTEN ON TCPv6
    addrsv6 = "::";
    ret = uv_ip6_addr(addrsv6, ctx->config.bind_port, &addr.addr6);
    CHECK(0 == ret);
    ret = server_tcp_launch(loop, &addr.addr);
    BREAK_ON_FALSE(0 == ret);

    // LISTEN ON UDPv6
    ret = server_dgram_launch(loop, &addr.addr);
    BREAK_ON_FALSE(0 == ret);

    uv_async_init(loop, &exit_async.async, server_exit_async_cb);

    success = true;

    ssnetio_on_bind("0.0.0.0", ctx->config.bind_port);

    // uv_run returns 0 when all handles are closed;
    // a non-zero return indicates uv_stop was called, or live handles remain
    ret = uv_run(loop, UV_RUN_DEFAULT);
    if (ret != 0) {
        // There are still active handles; walk them for cleanup
        uv_walk(loop, server_handle_walk_callback, NULL);
        uv_run(loop, UV_RUN_DEFAULT);
    } else {
        // Normally should not reach here
    }


    uv_loop_close(loop);

    // MORE RESOURCE CLEAN
    memset(&srv_ctx, 0, sizeof(srv_ctx));

    BREAK_LABEL:

        if (!success) {
            ssnetio_on_msg(LOG_ERROR,"tcp/udp server launch failed");
        }

    return ret;
}


// Callback for uv_walk to close all handles in the loop
// ReSharper disable once CppParameterMayBeConstPtrOrRef
static void server_handle_walk_callback(uv_handle_t* Handle, void* arg) {
    // uv_handle_type type = uv_handle_get_type(Handle);
    // const uv_loop_t* loop = uv_handle_get_loop(Handle);

    // In this loop, we only have listener and async handles;
    // no extra cleanup is needed, just close them directly
    if (!uv_is_closing(Handle)) {
        uv_close(Handle, NULL);
    }
}


// ReSharper disable once CppParameterMayBeConstPtrOrRef
static void server_exit_async_cb(uv_async_t* handle) {
    (void)handle;

    uv_stop(uv_default_loop());
}


void ssnetio_server_stop(void) {

    uv_async_send(&exit_async.async);
}
