/**
 *  Copyright 2025, LeNidViolet.
 *  Created by LeNidViolet on 2025/7/27.
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
#include <stdio.h>
#include "shadowsocks-crypto/shadowsocks-crypto.h"


void on_bind(const char *host, unsigned short port) {
    printf("BIND ON %s:%d\n", host, port);
}

void on_msg(int level, const char *msg) {
    if ( level <= 2 )
        printf("%d %s\n", level, msg);
}

void on_stream_connection_made(
    const char *domain_local,
    const char *addr_local,
    unsigned short port_local,
    const char *domain_remote,
    const char *addr_remote,
    unsigned short port_remote,
    int stream_index) {
    (void)stream_index;
    printf("CONNECTION: %s:%d -> %s:%d\n",
           domain_local ? domain_local : addr_local, port_local,
           domain_remote ? domain_remote : addr_remote, port_remote);
}

void on_stream_teardown(int stream_index) {
    (void)stream_index;
}

void on_plain_stream(const char *data, size_t data_len, bool send_out, int stream_index) {

    (void)data;
    (void)data_len;
    (void)send_out;
    (void)stream_index;
}


void on_dgram_connection_made(
    const char *domain_local,
    const char *addr_local,
    unsigned short port_local,
    const char *domain_remote,
    const char *addr_remote,
    unsigned short port_remote,
    int dgram_index)  {
    (void)dgram_index;
    printf("UDP: %s:%d -> %s:%d\n",
           domain_local ? domain_local : addr_local, port_local,
           domain_remote ? domain_remote : addr_remote, port_remote);
}

void on_dgram_teardown(int dgram_index) {
    (void)dgram_index;
}


void on_plain_dgram(const char *data, size_t data_len, bool send_out, int dgram_index) {
    (void)data;
    (void)data_len;
    (void)send_out;
    (void)dgram_index;
}



int main() {
    sscrypto_ctx ctx = { 0 };
    ctx.config.root_cert = "/Users/raven/Documents/macbook/root.crt";
    ctx.config.root_key = "/Users/raven/Documents/macbook/root.key";
    ctx.config.bind_port = 7110;
    ctx.config.password = "123456";
    ctx.config.method = "AES-256-CFB";
    ctx.config.idel_timeout = 120;

    ctx.callbacks.on_bind = on_bind;
    ctx.callbacks.on_msg = on_msg;

    ctx.callbacks.on_stream_connection_made = on_stream_connection_made;
    ctx.callbacks.on_stream_teardown = on_stream_teardown;
    ctx.callbacks.on_plain_stream = on_plain_stream;

    ctx.callbacks.on_dgram_connection_made = on_dgram_connection_made;
    ctx.callbacks.on_dgram_teardown = on_dgram_teardown;
    ctx.callbacks.on_plain_dgram = on_plain_dgram;

    sscrypto_launch(&ctx);

    return 0;
}
