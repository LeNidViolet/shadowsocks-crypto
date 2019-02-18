/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/7/26.
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

#ifndef SHADOWSOCKS_NETIO_H
#define SHADOWSOCKS_NETIO_H

#include <stddef.h>
#include "hdr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_SS_SERVER_BIND_HOST             ("0.0.0.0")
#define DEFAULT_SS_SERVER_BIND_PORT             (14450)
#define DEFAULT_SS_SERVER_IDEL_TIMEOUT          (60 * 1000)

#define DEFAULT_SS_CLIENT_BIND_HOST             ("127.0.0.1")
#define DEFAULT_SS_CLIENT_BIND_PORT             (14550)
#define DEFAULT_SS_CLIENT_IDEL_TIMEOUT          (60 * 1000)

#define MAX_S5_HDR_LEN                          (255 + 6)
#define MAX_SS_TCP_PAYLOAD_LEN                  (10 * 1024)
#define MAX_SS_UDP_PAYLOAD_LEN                  (512)
#define MAX_SS_SALT_LEN                         (32)
#define MAX_SS_TAG_LEN                          (16)

#define MAX_SS_TCP_WRAPPER_LEN     (2 + MAX_SS_TAG_LEN + MAX_SS_TAG_LEN + MAX_SS_SALT_LEN)
#define MAX_SS_UDP_WRAPPER_LEN     (MAX_SS_TAG_LEN + MAX_SS_SALT_LEN)

#define MAX_SS_TCP_FRAME_LEN       (MAX_SS_TCP_PAYLOAD_LEN + MAX_S5_HDR_LEN + MAX_SS_TCP_WRAPPER_LEN)
#define MAX_SS_UDP_FRAME_LEN       (MAX_SS_UDP_PAYLOAD_LEN + MAX_S5_HDR_LEN + MAX_SS_UDP_WRAPPER_LEN)

typedef struct SSNETIO_BASE_CONFIG{
    const char *bind_host;
    unsigned short bind_port;
    unsigned int idel_timeout;

    /* Client sode only. */
    const char *ss_srv_addr;
    unsigned short ss_srv_port;
}SSNETIO_BASE_CONFIG;



typedef struct SSNETIO_CALLBACKS{
    /* Event Notify, Can be NULL */
    void (*on_msg)(int level, const char *msg);
    void (*on_bind)(const char *host, unsigned short port);
    void (*on_stream_connection_made)(ADDRESS_PAIR *addr, void *ctx);

    /* A new request coming,
     * set data to a context associate with this session,
     * */
    void (*on_new_stream)(ADDRESS *addr, void **ctx, void *stream_id);
    void (*on_stream_teardown)(void *ctx);

    /* A new udp dgram request
     * set data to a context associate with it
     * */
    void (*on_new_dgram)(ADDRESS_PAIR *addr, void **ctx);
    void (*on_dgram_teardown)(void *ctx);


    int (*on_plain_stream)(MEM_RANGE *buf, int direct, void *ctx);
    void (*on_plain_dgram)(MEM_RANGE *buf, int direct, void *ctx);


    /* Data Event, CANNOT be NULL */

    /* Encrypt data before send back, decrypt data after recv.
     * return 0 if success.
     */
    int (*on_stream_encrypt)(MEM_RANGE *buf, void *ctx);
    int (*on_stream_decrypt)(MEM_RANGE *buf, void *ctx);

    int (*on_dgram_encrypt)(MEM_RANGE *buf);
    int (*on_dgram_decrypt)(MEM_RANGE *buf);
}SSNETIO_CALLBACKS;

typedef struct SSNETIO_CTX{
    SSNETIO_BASE_CONFIG config;
    SSNETIO_CALLBACKS callbacks;
}SSNETIO_CTX;


/* Negative value returned when error occur, 0 if success */
int ssnetio_server_launch(SSNETIO_CTX *ctx);
void ssnetio_server_port(IOCTL_PORT *port);

/* Negative value returned when error occur, 0 if success */
int ssnetio_client_launch(SSNETIO_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif //SHADOWSOCKS_NETIO_H
