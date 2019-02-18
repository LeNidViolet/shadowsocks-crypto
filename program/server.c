/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/14.
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

void on_stream_connection_made(ADDRESS_PAIR *addr, void *ctx) {
    (void)ctx;
    printf("CONNECTION: %s:%d -> %s:%d\n",
        addr->local->host, addr->local->port,
        addr->remote->host, addr->remote->port);
}

void on_bind(const char *host, unsigned short port) {
    printf("BIND ON %s:%d\n", host, port);
}

void on_msg(int level, const char *msg) {
    printf("%d %s\n", level, msg);
}

int main() {
    SSCRYPTO_CTX ctx = { 0 };
    ctx.config.as_server = 1;
    ctx.config.bind_host = "127.0.0.1";
    ctx.config.bind_port = 14450;
    ctx.config.password = "123qwe";
    ctx.config.method = "AES-256-CFB";
    ctx.config.idel_timeout = 60 * 1000;

    ctx.callbacks.on_stream_connection_made = on_stream_connection_made;
    ctx.callbacks.on_bind = on_bind;
    ctx.callbacks.on_msg = on_msg;

    sscrypto_launch(&ctx);

    return 0;
}
