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
#ifndef SHADOWSOCKS_CRYPTO_SHADOWSOCKS_CRYPTO_H
#define SHADOWSOCKS_CRYPTO_SHADOWSOCKS_CRYPTO_H

#include <stddef.h>

typedef struct {
    const char *bind_host;
    unsigned short bind_port;
    unsigned int idel_timeout;  /* 秒 */

    const char *password;
    const char *method;
} sscrypto_cfg;

typedef struct {
    void (*on_msg)(int level, const char *msg);
    void (*on_bind)(const char *host, unsigned short port);
    void (*on_stream_connection_made)(
        const char *addr_local,
        unsigned short port_local,
        const char *addr_remote,
        unsigned short port_remote,
        int stream_index);
    void (*on_stream_teardown)(int stream_index);

    /* A new udp dgram request
     * set data to a context associate with it
     * */
    void (*on_dgram_connection_made)(
        const char *addr_local,
        unsigned short port_local,
        const char *addr_remote,
        unsigned short port_remote,
        int dgram_index);
    void (*on_dgram_teardown)(int dgram_index);


    void (*on_plain_stream)(const char *data, size_t data_len, int direct, int stream_index);
    void (*on_plain_dgram)(const char *data, size_t data_len, int direct, int dgram_index);
} sscrypto_callback;

typedef struct {
    // 基础配置
    sscrypto_cfg config;

    // 事件回调表
    sscrypto_callback callbacks;
} sscrypto_ctx;


/**
 * @brief                       启动SS, 成功时阻塞至结束为止
 *
 * @param ctx                   SS配置
 *
 * @return                      0 on success
 */
int sscrypto_launch(const sscrypto_ctx *ctx);
void sscrypto_stop();

#endif //SHADOWSOCKS_CRYPTO_SHADOWSOCKS_CRYPTO_H
