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

#include "../comm/comm.h"
#include "uv.h"

/* Session states. */
enum sess_state {
    s_handshake,        /* Wait for client handshake. */
    s_req_lookup,       /* Wait for upstream hostname DNS lookup to complete. */
    s_dnsovertcp_lookup,
    s_req_connect,      /* Wait for uv_tcp_connect() to complete. */
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
} endpoint;


typedef struct {
    unsigned char rdstate;
    unsigned char wrstate;
    unsigned int idle_timeout;
    struct proxy_node_ *pn;  /* Backlink */
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
    } t;
    char slab[MAX_SS_TCP_FRAME_LEN];

    address peer;
    buf_range ss_buf;
} connection;

typedef struct proxy_node_{
    int state;
    unsigned int index;
    uv_loop_t *loop;

    connection incoming;  /* Connection with the SOCKS client. */
    connection outgoing;  /* Connection with upstream. */
    int outstanding;

    char link_info[128];

    void *ctx;
} proxy_node;


/* URIL.C */
int  sockaddr_to_str(const struct sockaddr *addr, address *addr_s, int set_port);
void sockaddr_cpy(const struct sockaddr *src, struct sockaddr *dst);
int  sockaddr_equal(const struct sockaddr *src, const struct sockaddr *dst, int cmp_port);
void sockaddr_set_port(struct sockaddr *addr, unsigned short port);
int  str_tcp_endpoint(const uv_tcp_t *tcp_handle, endpoint ep, address *addr_s);

enum {
    s5_invalid_length = -1,
    s5_invalid_version = -2,
    s5_invalid_method = -3
};

/* Parse the host/ip and port from incoming data.
 * Set data_base AND data_len, to the actual data range.
 * return 0 if success.
 */
int s5_parse_addr(buf_range *buf, address *addr);

/* HANDLER.C */
void ssnetio_on_msg(int level, const char *format, ...);
void ssnetio_on_bind(const char *host, unsigned short port);
void ssnetio_on_connection_made(proxy_node *pn);
void ssnetio_on_new_stream(connection *conn);
void ssnetio_on_stream_teardown(proxy_node *pn);
void ssnetio_on_new_dgram(address *local, address *remote, void **ctx);
void ssnetio_on_dgram_teardown(void *ctx);
int  ssnetio_on_stream_encrypt(connection *conn, int offset);
int  ssnetio_on_stream_decrypt(connection *conn, int offset);
int  ssnetio_on_dgram_encrypt(buf_range *buf, int offset);
int  ssnetio_on_dgram_decrypt(buf_range *buf, int offset);
int  ssnetio_on_plain_stream(connection *conn);
void ssnetio_on_plain_dgram(buf_range *buf, int direct, void *ctx);

int  ssnetio_write_stream_out(
    const char *buf, size_t len, int direct, void *stream_id);
void ssnetio_stream_pause(void *stream_id, int direct, int pause);





int  server_dns_launch(uv_loop_t *loop, const struct sockaddr *addr);
void server_dns_stop();

int  server_tcp_launch(uv_loop_t *loop, const struct sockaddr *addr);
void server_tcp_stop();

int  server_dgram_launch(uv_loop_t *loop, const struct sockaddr *addr);
void server_dgram_stop();



int  do_kill(proxy_node *pn);
void conn_timer_reset(connection *conn);
void conn_read(connection *conn);

#endif //SHADOWSOCKS_NETIO_INTERNAL_H
