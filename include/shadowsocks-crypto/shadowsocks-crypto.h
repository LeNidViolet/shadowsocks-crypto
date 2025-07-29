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
#ifndef SHADOWSOCKS_CRYPTO_SHADOWSOCKS_CRYPTO_H
#define SHADOWSOCKS_CRYPTO_SHADOWSOCKS_CRYPTO_H

#include <stddef.h>
#include <stdbool.h>

typedef struct {
    unsigned short bind_port;
    unsigned int idel_timeout;  /* 秒 */

    const char *password;
    const char *method;

    const char *root_cert;      /* 根证书 文件路径 */
    const char *root_key;       /* 根证书秘钥 文件路径 */
} shadowsocks_crypto_cfg;

typedef void (*FN_CALLBACK_ONMSG)   (int level, const char *msg);
typedef void (*FN_CALLBACK_ONBIND)  (const char *host, unsigned short port);
typedef void (*FN_CALLBACK_ONSTREAMCONNECTIONMADE) (
    const char *domain_local,
    const char *ip_local,
    unsigned short port_local,
    const char *domain_remote,
    const char *ip_remote,
    unsigned short port_remote,
    int stream_index);
typedef void (*FN_CALLBACK_ONSTREAMTEARDOWN) (int stream_index);
typedef void (*FN_CALLBACK_ONDGRAMCONNECTIONMADE) (
    const char *domain_local,
    const char *ip_local,
    unsigned short port_local,
    const char *domain_remote,
    const char *ip_remote,
    unsigned short port_remote,
    int dgram_index);
typedef void (*FN_CALLBACK_ONDGRAMTEARDOWN) (int dgram_index);
typedef void (*FN_CALLBACK_ONPLAINSTREAM) (const char *data, size_t data_len, bool send_out, int stream_index);
typedef void (*FN_CALLBACK_ONPLAINDGRAM) (const char *data, size_t data_len, bool send_out, int dgram_index);

typedef struct {
    FN_CALLBACK_ONMSG                   on_msg;
    FN_CALLBACK_ONBIND                  on_bind;
    FN_CALLBACK_ONSTREAMCONNECTIONMADE  on_stream_connection_made;
    FN_CALLBACK_ONSTREAMTEARDOWN        on_stream_teardown;

    /* A new udp dgram request
     * set data to a context associate with it
     * */
    FN_CALLBACK_ONDGRAMCONNECTIONMADE   on_dgram_connection_made;
    FN_CALLBACK_ONDGRAMTEARDOWN         on_dgram_teardown;

    FN_CALLBACK_ONPLAINSTREAM           on_plain_stream;
    FN_CALLBACK_ONPLAINDGRAM            on_plain_dgram;
} shadowsocks_crypto_callback;

typedef struct {
    // 基础配置
    shadowsocks_crypto_cfg config;

    // 事件回调表
    shadowsocks_crypto_callback callbacks;
} shadowsocks_crypto_ctx;


/**
 * @brief                       启动SS, 成功时阻塞至结束为止
 *
 * @param ctx                   SS配置
 *
 * @return                      0 on success
 */
int shadowsocks_crypto_launch(const shadowsocks_crypto_ctx *ctx);
void shadowsocks_crypto_stop();

#endif //SHADOWSOCKS_CRYPTO_SHADOWSOCKS_CRYPTO_H
