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
#include "internal.h"

CRYPTO_ENV CryptoEnv = { 0 };

int ssnetio_server_launch(SSCRYPTO_CTX *ctx);
void ssnetio_server_port(IOCTL_PORT *port);
int tlsflat_init(IOCTL_PORT *port);
void tlsflat_clear(void);

int sscrypto_launch(SSCRYPTO_CTX *ctx) {
    int ret = -1;
    IOCTL_PORT io_port;

    BREAK_ON_NULL(ctx);
    BREAK_ON_NULL(ctx->config.method);
    BREAK_ON_NULL(ctx->config.password);

    CryptoEnv.method = get_method_by_name(ctx->config.method);
    BREAK_ON_NULL(CryptoEnv.method);

    CHECK(0 == gen_key(ctx->config.password, CryptoEnv.key, CryptoEnv.method->key_len));

    /* Save caller's callbacks */
    CryptoEnv.callbacks = ctx->callbacks;


    /* 初始化 TLS 部分 */
    ssnetio_server_port(&io_port);
    ret = tlsflat_init(&io_port);
    if ( 0 != ret ) {
        sscrypto_on_msg(1, "Tlsflat init Failed");
        BREAK_NOW;
    }

    /* 初始化加密解密单元 */
    init_crypt_unit();

    /* 启动SS NETIO, 开始监听 */
    ret = ssnetio_server_launch(ctx);

    /* 释放加密解密单元资源 */
    free_crypt_unit();

    /* 释放 TLS 资源 */
    tlsflat_clear();

    sscrypto_on_msg(3, "Program Exiting");

BREAK_LABEL:

    return ret;
}
