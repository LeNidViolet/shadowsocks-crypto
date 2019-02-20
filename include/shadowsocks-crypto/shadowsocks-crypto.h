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

#define MAX_S5_HDR_LEN                          (255 + 6)
#define MAX_SS_TCP_PAYLOAD_LEN                  (10 * 1024)
#define MAX_SS_UDP_PAYLOAD_LEN                  (512)
#define MAX_SS_SALT_LEN                         (32)
#define MAX_SS_TAG_LEN                          (16)

#define MAX_SS_TCP_WRAPPER_LEN     (2 + MAX_SS_TAG_LEN + MAX_SS_TAG_LEN + MAX_SS_SALT_LEN)
#define MAX_SS_UDP_WRAPPER_LEN     (MAX_SS_TAG_LEN + MAX_SS_SALT_LEN)

#define MAX_SS_TCP_FRAME_LEN       (MAX_SS_TCP_PAYLOAD_LEN + MAX_S5_HDR_LEN + MAX_SS_TCP_WRAPPER_LEN)
#define MAX_SS_UDP_FRAME_LEN       (MAX_SS_UDP_PAYLOAD_LEN + MAX_S5_HDR_LEN + MAX_SS_UDP_WRAPPER_LEN)

enum {
    STREAM_UP,      /* local -> remote */
    STREAM_DOWN     /* remote -> local */
};

enum {
    PASS,
    NEEDMORE,
    REJECT,
    TERMINATE
};

typedef struct ADDRESS{
    char host[64];      /* HostName or IpAddress */
    unsigned short port;
} ADDRESS;

typedef struct ADDRESS_PAIR{
    ADDRESS *local;
    ADDRESS *remote;
} ADDRESS_PAIR;

typedef struct MEM_RANGE{
    char *buf_base;
    size_t buf_len;
    char *data_base;
    size_t data_len;
} MEM_RANGE;

typedef void (*write_stream_out_callback)(void* param, int direct, int status, void *ctx);
typedef struct IOCTL_PORT{
    /* Interface for send data out */
    int (*write_stream_out)(
        MEM_RANGE *buf, int direct, void *stream_id,
        write_stream_out_callback callback, void *param);

    void (*stream_pause)(void *stream_id, int direct, int pause);
} IOCTL_PORT;

typedef struct SSNETIO_BASE_CONFIG{
    const char *bind_host;
    unsigned short bind_port;
    unsigned int idel_timeout;

    /* Client sode only. */
    const char *ss_srv_addr;
    unsigned short ss_srv_port;
} SSNETIO_BASE_CONFIG;

typedef struct SSNETIO_CTX{
    SSNETIO_BASE_CONFIG config;
} SSNETIO_CTX;

typedef struct SSCRYPTO_BASE_CONFIG{
    const char *bind_host;
    unsigned short bind_port;
    unsigned int idel_timeout;

    /* Client sode only. */
    const char *ss_srv_addr;
    unsigned short ss_srv_port;

    const char *password;
    const char *method;

    int as_server;  /* 0=client, server otherwise */
} SSCRYPTO_BASE_CONFIG;

typedef struct SSCRYPTO_CALLBACKS{
    void (*on_msg)(int level, const char *msg);
    void (*on_bind)(const char *host, unsigned short port);
    void (*on_stream_connection_made)(ADDRESS_PAIR *addr, int stream_index);
    void (*on_stream_teardown)(int stream_index);

    /* A new udp dgram request
     * set data to a context associate with it
     * */
    void (*on_new_dgram)(ADDRESS_PAIR *addr, int dgram_index);
    void (*on_dgram_teardown)(int dgram_index);


    int (*on_plain_stream)(const char *data, size_t data_len, int direct, int stream_index);
    void (*on_plain_dgram)(const char *data, size_t data_len, int direct, int dgram_index);
} SSCRYPTO_CALLBACKS;

typedef struct SSCRYPTO_CTX{
    // 基础配置
    SSCRYPTO_BASE_CONFIG config;

    // 事件回调表
    SSCRYPTO_CALLBACKS callbacks;
} SSCRYPTO_CTX;


/**
 * @brief                       启动SS, 成功时阻塞至结束为止
 *
 * @param ctx                   SS配置
 *
 * @return                      0 on success
 */
int sscrypto_launch(SSCRYPTO_CTX *ctx);

#endif //SHADOWSOCKS_CRYPTO_SHADOWSOCKS_CRYPTO_H
