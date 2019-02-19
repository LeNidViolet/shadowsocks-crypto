/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/13.
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

CRYPTO_ENV CryptoEnv = { 0 };

int ssnetio_server_launch(SSNETIO_CTX *ctx);
int ssnetio_client_launch(SSNETIO_CTX *ctx);
void ssnetio_server_port(IOCTL_PORT *port);

int sscrypto_launch(SSCRYPTO_CTX *ctx) {
    int ret = -1;
    SSNETIO_CTX netioctx = { 0 };

    BREAK_ON_NULL(ctx);
    BREAK_ON_NULL(ctx->config.method);
    BREAK_ON_NULL(ctx->config.password);

    CryptoEnv.method = get_method_by_name(ctx->config.method);
    BREAK_ON_NULL(CryptoEnv.method);

    CHECK(0 == gen_key(ctx->config.password, CryptoEnv.key, CryptoEnv.method->key_len));

    netioctx.config.bind_host       = ctx->config.bind_host;
    netioctx.config.bind_port       = ctx->config.bind_port;
    netioctx.config.ss_srv_addr     = ctx->config.ss_srv_addr;
    netioctx.config.ss_srv_port     = ctx->config.ss_srv_port;
    netioctx.config.idel_timeout    = ctx->config.idel_timeout;

    /* Save caller's callbacks */
    CryptoEnv.callbacks = ctx->callbacks;

    init_calback_unit();

    /* 启动SS NETIO, 开始监听 */
    if ( 0 == ctx->config.as_server ) {
        ret = ssnetio_client_launch(&netioctx);
    } else {
        ret = ssnetio_server_launch(&netioctx);
    }

    free_callback_unit();

BREAK_LABEL:

    return ret;
}

void sscrypto_server_port(IOCTL_PORT *port) {
    ssnetio_server_port(port);
}
