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

#ifndef SHADOWSOCKS_NETIO_INTERNAL_H
#define SHADOWSOCKS_NETIO_INTERNAL_H

#include <assert.h>
#include <stdlib.h>
#include "shadowsocks-crypto/comm.h"
#include "uv.h"
/* Session states. */
enum sess_state {
    s_handshake,        /* Wait for client handshake. */
    s_req_start,        /* Start waiting for request data. */
    s_req_parse,        /* Wait for request data. */
    s_req_lookup,       /* Wait for upstream hostname DNS lookup to complete. */
    s_req_connect,      /* Wait for uv_tcp_connect() to complete. */
    s_proxy_ready,
    s_proxy_start,      /* Connected. Start piping data. */
    s_proxy,            /* Connected. Pipe data back and forth. */
    s_kill,             /* Tear down session. */
    s_almost_dead_0,    /* Waiting for finalizers to complete. */
    s_almost_dead_1,    /* Waiting for finalizers to complete. */
    s_almost_dead_2,    /* Waiting for finalizers to complete. */
    s_almost_dead_3,    /* Waiting for finalizers to complete. */
    s_almost_dead_4,    /* Waiting for finalizers to complete. */
    s_dead,             /* Dead. Safe to free now. */

    s_max
};

enum conn_state {
    c_busy,  /* Busy; waiting for incoming data or for a write to complete. */
    c_done,  /* Done; read incoming data or write finished. */
    c_stop,  /* Stopped. */
    c_dead
};

typedef enum {
    peer,
    sock
}endpoint;

typedef struct SSNETIO_BUF{
    char *buf_base;
    size_t buf_len;
    char *data_base;
    size_t data_len;
}SSNETIO_BUF;

typedef struct {
    unsigned char rdstate;
    unsigned char wrstate;
    unsigned int idle_timeout;
    struct PROXY_NODE *pn;  /* Backlink */
    ssize_t result;
    union {
        uv_handle_t handle;
        uv_stream_t stream;
        uv_tcp_t tcp;
        uv_udp_t udp;
    } handle;
    uv_timer_t timer_handle;  /* For detecting timeouts. */
    uv_write_t write_req;
    /* We only need one of these at a time so make them share memory. */
    union {
        uv_getaddrinfo_t addrinfo_req;
        uv_connect_t connect_req;
        uv_req_t req;
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
        char slab[MAX_SS_TCP_FRAME_LEN];
    } t;

    ADDRESS peer;
    SSNETIO_BUF ss_buf;
} CONN;

typedef struct PROXY_NODE {
    int state;
    unsigned int index;
    uv_loop_t *loop;

    CONN incoming;  /* Connection with the SOCKS client. */
    CONN outgoing;  /* Connection with upstream. */
    int outstanding;

    char link_info[128];

    void *ctx;
} PROXY_NODE;




#define htons_u(x)          (unsigned short)( (((x) & 0xffu) << 8u) | (((x) & 0xff00u) >> 8u) )
#define ntohs_u(x)          htons_u(x)

#define ntohl_u(x)        ( (((x) & 0xffu) << 24u) | \
                            (((x) & 0xff00u) << 8u) | \
                            (((x) & 0xff0000u) >> 8u) | \
                            (((x) & 0xff000000) >> 24u) )
#define htonl_u(x)          ntohl_u(x)

/* URIL.C */
int str_sockaddr(const struct sockaddr *addr, ADDRESS *addr_s);
void cpy_sockaddr(const struct sockaddr *src, struct sockaddr *dst);
int equal_sockaddr(const struct sockaddr *src, struct sockaddr *dst);
void set_sockaddr_port(struct sockaddr *addr, unsigned short port);
int str_tcp_endpoint(const uv_tcp_t *tcp_handle, endpoint ep, ADDRESS *addr_s);

enum {
    s5_invalid_length = -1,
    s5_invalid_version = -2,
    s5_invalid_method = -3
};

int s5_simple_check(const char *data, size_t data_len);

/* Parse the host/ip and port from incoming data.
 * Set data_base AND data_len, to the actual data range.
 * return 0 if success.
 */
int s5_parse_addr(SSNETIO_BUF *buf, ADDRESS *addr);

/* HANDLER.C */
void ssnetio_on_msg(int level, const char *format, ...);
void ssnetio_on_bind(const char *host, unsigned short port);
void ssnetio_on_connection_made(PROXY_NODE *pn);
void ssnetio_on_new_stream(CONN *conn);
void ssnetio_on_stream_teardown(PROXY_NODE *pn);
void ssnetio_on_new_dgram(ADDRESS *local, ADDRESS *remote, void **ctx);
void ssnetio_on_dgram_teardown(void *ctx);
int ssnetio_on_stream_encrypt(CONN *conn, int offset);
int ssnetio_on_stream_decrypt(CONN *conn, int offset);
int ssnetio_on_dgram_encrypt(SSNETIO_BUF *buf, int offset);
int ssnetio_on_dgram_decrypt(SSNETIO_BUF *buf, int offset);
int ssnetio_on_plain_stream(CONN *conn);
void ssnetio_on_plain_dgram(SSNETIO_BUF *buf, int direct, void *ctx);

int ssnetio_write_stream_out(
    MEM_RANGE *buf, int direct, void *stream_id,
    write_stream_out_callback callback, void *param);
void ssnetio_stream_pause(void *stream_id, int direct, int pause);

void do_bind(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);
void on_connection(uv_stream_t *server, int status);
void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
void conn_read(CONN *conn);
void conn_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
void conn_write(CONN *conn, const void *data, unsigned int len);
void conn_write_done(uv_write_t *req, int status);
void conn_connect_done(uv_connect_t *req, int status);
void conn_close(CONN *conn);
void conn_close_done(uv_handle_t *handle);
void conn_timer_reset(CONN *conn);
int conn_cycle(const char *who, CONN *a, CONN *b);

int dgram_read_local(uv_udp_t *handle);

int do_proxy_start(PROXY_NODE *pn);
int do_proxy(CONN *sender);
int do_kill(PROXY_NODE *pn);
int do_almost_dead(PROXY_NODE *pn);
int do_clear(PROXY_NODE *pn);

void conn_timer_expire_server(uv_timer_t *handle);
void do_next_server(CONN *sender);


/* EXTERNAL FUNCTION */
// 向上调用至CRYPTO对用的回调中
void sscrypto_on_msg(int level, const char *msg);
void sscrypto_on_bind(const char *host, unsigned short port);
void sscrypto_on_stream_connection_made(ADDRESS_PAIR *addr, void *ctx);
void sscrypto_on_new_stream(const ADDRESS *addr, void **ctx, void *stream_id);
void sscrypto_on_stream_teardown(void *ctx);
void sscrypto_on_new_dgram(const ADDRESS_PAIR *addr, void **ctx);
void sscrypto_on_dgram_teardown(void *ctx);
int sscrypto_on_plain_stream(const MEM_RANGE *buf, int direct, void *ctx);
void sscrypto_on_plain_dgram(const MEM_RANGE *buf, int direct, void *ctx);
int sscrypto_on_stream_encrypt(MEM_RANGE *buf, void *ctx);
int sscrypto_on_stream_decrypt(MEM_RANGE *buf, void *ctx);
int sscrypto_on_dgram_encrypt(MEM_RANGE *buf);
int sscrypto_on_dgram_decrypt(MEM_RANGE *buf);

#endif //SHADOWSOCKS_NETIO_INTERNAL_H
