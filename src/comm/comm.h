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
#ifndef SHADOWSOCKS_CRYPTO_COMM_H
#define SHADOWSOCKS_CRYPTO_COMM_H

#include <stddef.h>
#include <assert.h>
#include <stdlib.h>

#define BREAK_LABEL                                     \
    cleanup

#define BREAK_ON_FAILURE_WITH_LABEL(_status, label)     \
if ( (_status) != 0 )                                   \
    goto label

#define BREAK_ON_FAILURE(_status)                       \
    BREAK_ON_FAILURE_WITH_LABEL(_status, BREAK_LABEL)

#define BREAK_ON_NULL_WITH_LABEL(value, label)          \
if ( !(value) )                                         \
    goto label

#define BREAK_ON_NULL(_value)                           \
    BREAK_ON_NULL_WITH_LABEL(_value, BREAK_LABEL)

#define BREAK_ON_FALSE        BREAK_ON_NULL

#define BREAK_NOW                                       \
    goto BREAK_LABEL

#if defined(NDEBUG)
# define ASSERT(exp)
# define CHECK(exp)     do { if (!(exp)) abort(); } while (0)
# define DEBUG_CHECKS (0)
#else
# define ASSERT(exp)  assert(exp)
# define CHECK(exp)   assert(exp)
# define DEBUG_CHECKS (1)
#endif
#define ENSURE(exp)     do { if (!(exp)) abort(); } while (0)
#define UNREACHABLE()   CHECK(!"Unreachable code reached.")

#define CONTAINER_OF(ptr, type, field)                                        \
  ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))

#define MAX_S5_HDR_LEN                          (255 + 6)
#define MAX_SS_TCP_PAYLOAD_LEN                  (32 * 1024)
#define MAX_SS_UDP_PAYLOAD_LEN                  (1600)
#define MAX_SS_SALT_LEN                         (32)
#define MAX_SS_TAG_LEN                          (16)

#define MAX_SS_TCP_WRAPPER_LEN     (2 + MAX_SS_TAG_LEN + MAX_SS_TAG_LEN + MAX_SS_SALT_LEN)
#define MAX_SS_UDP_WRAPPER_LEN     (MAX_SS_TAG_LEN + MAX_SS_SALT_LEN)

#define MAX_SS_TCP_FRAME_LEN       (MAX_SS_TCP_PAYLOAD_LEN + MAX_S5_HDR_LEN + MAX_SS_TCP_WRAPPER_LEN)
#define MAX_SS_UDP_FRAME_LEN       (MAX_SS_UDP_PAYLOAD_LEN + MAX_S5_HDR_LEN + MAX_SS_UDP_WRAPPER_LEN)


#define htons_u(x)          (unsigned short)( (((x) & 0xffu) << 8u) | (((x) & 0xff00u) >> 8u) )
#define ntohs_u(x)          htons_u(x)

#define ntohl_u(x)        ( (((x) & 0xffu) << 24u) | \
                            (((x) & 0xff00u) << 8u) | \
                            (((x) & 0xff0000u) >> 8u) | \
                            (((x) & 0xff000000) >> 24u) )
#define htonl_u(x)          ntohl_u(x)


typedef struct {
    char ip[64];
    char domain[64];      /* HostName or IpAddress */
    unsigned short port;
} ADDRESS;

typedef struct {
    ADDRESS *local;
    ADDRESS *remote;
} ADDRESS_PAIR;

typedef struct {
    char *buf_base;
    size_t buf_len;
    char *data_base;
    size_t data_len;
} BUF_RANGE;

typedef void (*write_stream_out_callback)(void* param, int direct, int status, void *ctx);
typedef struct {
    /* Interface for send data out */
    int (*write_stream_out)(
        const char *buf, size_t len, int direct, void *stream_id);

    void (*stream_pause)(void *stream_id, int direct, int pause);
} ioctl_port;

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

enum {
    LOG_ERROR,
    LOG_WARN,
    LOG_KEY,
    LOG_INFO,
    LOG_DEBUG,
};

#endif //SHADOWSOCKS_CRYPTO_COMM_H
