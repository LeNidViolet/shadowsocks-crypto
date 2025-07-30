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
#include <stdlib.h>
#include "internal.h"

crypto_env shadowsocks_env = { 0 };
static int shadowsocks_running = 0;

int shadowsocks_crypto_launch(const shadowsocks_crypto_ctx *ctx) {
    int ret = -1;
    ioctl_port io_port;

    BREAK_ON_FALSE(0 == shadowsocks_running);

    BREAK_ON_NULL(ctx);
    BREAK_ON_NULL(ctx->config.method);
    BREAK_ON_NULL(ctx->config.password);
    BREAK_ON_NULL(ctx->config.root_cert);
    BREAK_ON_NULL(ctx->config.root_key);

    shadowsocks_env.method = get_method_by_name(ctx->config.method);
    BREAK_ON_NULL(shadowsocks_env.method);


    /* 根据设置的密码生成加密用的KEY */
    CHECK(0 == gen_key(ctx->config.password, shadowsocks_env.key, shadowsocks_env.method->key_len));


    /* 保存回调 */
    shadowsocks_env.callbacks = ctx->callbacks;


    /* 获取NETIO底层发送数据等接口.需要在TLSFLAT中使用 */
    ssnetio_server_port(&io_port);
    /* 初始化 TLS 部分 */
    ret = tlsflat_init(
        &io_port,
        ctx->config.root_cert,
        ctx->config.root_key);
    if ( 0 != ret ) {
        sscrypto_on_msg(LOG_ERROR, "tlsflat init failed");
        BREAK_NOW;
    }


    /* 初始化加密解密单元 */
    init_crypt_unit();

    shadowsocks_running = 1;

    /* 启动SS NETIO, 开始监听 */
    ret = ssnetio_server_launch(ctx);

    shadowsocks_running = 0;

    /* 释放加密解密单元资源 */
    free_crypt_unit();

    /* 释放 TLS 资源 */
    tlsflat_clear();

BREAK_LABEL:

    return ret;
}

void shadowsocks_crypto_stop() {
    if ( shadowsocks_running ) {
        ssnetio_server_stop();
        shadowsocks_running = 0;
    }
}
