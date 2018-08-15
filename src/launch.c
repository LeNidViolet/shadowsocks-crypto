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
#include "shadowsocks-netio/shadowsocks-netio.h"
#include "shadowsocks-crypto/shadowsocks-crypto.h"
#include "internal.h"

CRYPTO_ENV CryptoEnv = { 0 };

int sscrypto_launch(SSCRYPTO_CTX *ctx) {
    int ret = -1;
    SSNETIO_CTX netioctx = { 0 };

    BREAK_ON_NULL(ctx);

    if ( !ctx->config.method )
        ctx->config.method = DEFAULT_METHOD;
    if ( !ctx->config.password )
        ctx->config.password = DEFAULT_PASSWORD;

    CryptoEnv.method = get_method_by_name(ctx->config.method);
    BREAK_ON_NULL(CryptoEnv.method);

    CHECK(0 == gen_key(ctx->config.password, CryptoEnv.key, CryptoEnv.method->key_len));

    netioctx.config.bind_host       = ctx->config.bind_host;
    netioctx.config.bind_port       = ctx->config.bind_port;
    netioctx.config.ss_srv_addr     = ctx->config.ss_srv_addr;
    netioctx.config.ss_srv_port     = ctx->config.ss_srv_port;
    netioctx.config.idel_timeout    = ctx->config.idel_timeout;

    netioctx.callbacks.on_msg                       = ssnetio_on_msg;
    netioctx.callbacks.on_bind                      = ssnetio_on_bind;
    netioctx.callbacks.on_stream_connection_made    = ssnetio_on_stream_connection_made;
    netioctx.callbacks.on_new_stream                = ssnetio_on_new_stream;
    netioctx.callbacks.on_stream_teardown           = ssnetio_on_stream_teardown;
    netioctx.callbacks.on_new_dgram                 = ssnetio_on_new_dgram;
    netioctx.callbacks.on_dgram_teardown            = ssnetio_on_dgram_teardown;
    netioctx.callbacks.on_stream_encrypt            = ssnetio_on_stream_encrypt;
    netioctx.callbacks.on_stream_decrypt            = ssnetio_on_stream_decrypt;
    netioctx.callbacks.on_dgram_encrypt             = ssnetio_on_dgram_encrypt;
    netioctx.callbacks.on_dgram_decrypt             = ssnetio_on_dgram_decrypt;
    netioctx.callbacks.on_plain_stream              = ssnetio_on_plain_stream;
    netioctx.callbacks.on_plain_dgram               = ssnetio_on_plain_dgram;

    /* Save caller's callbacks */
    CryptoEnv.ori_cbs = ctx->callbacks;

    init_calback_unit();

    if ( 0 == ctx->config.as_server ) {
        ret = ssnetio_client_launch(&netioctx);
    } else {
        ret = ssnetio_server_launch(&netioctx);
    }

    free_callback_unit();

BREAK_LABEL:

    return ret;
}
