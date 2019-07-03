/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/7/31.
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

#include "shadowsocks-crypto/shadowsocks-crypto.h"
#include "internal.h"

extern SSCRYPTO_CTX srv_ctx;

static void conn_timer_expire(uv_timer_t *handle);
static void do_next(CONN *sender);
static void loop_walk_clear(uv_loop_t *loop);
static void loop_walk_cb(uv_handle_t* handle, void* arg);
static void loop_walk_close_done(uv_handle_t* handle);


void do_bind(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    address address = {0};
    unsigned int naddrs;
    unsigned short port;
    struct addrinfo *ai;
    uv_loop_t *loop;
    int ret = -1;
    union {
        struct sockaddr addr;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } s;
    uv_tcp_t *tcp_handle;
    uv_udp_t *udp_handle;
    SSNETIO_BUF *ss_buf;
    const unsigned short dns_port = 53;

    loop = uv_req_get_data((uv_req_t *)req);

    if ( status < 0 ) {
        ssnetio_on_msg(1, "uv_getaddrinfo failed: %s", uv_strerror(status));
        BREAK_NOW;
    }

    /* Just bind to ipv4 ipv6 address */
    naddrs = 0;
    for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
        if ( AF_INET == ai->ai_family  || AF_INET6 == ai->ai_family ) {
            naddrs++;
        }
    }
    BREAK_ON_NULL(naddrs);

    port = srv_ctx.config.bind_port;
    for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
        if ( AF_INET != ai->ai_family && AF_INET6 != ai->ai_family ) {
            continue;
        }

        if ( AF_INET == ai->ai_family ) {
            s.addr4 = *(const struct sockaddr_in *)ai->ai_addr;
            s.addr4.sin_port = htons_u(port);
        }
        else if ( AF_INET6 == ai->ai_family ) {
            s.addr6 = *(const struct sockaddr_in6 *)ai->ai_addr;
            s.addr6.sin6_port = htons_u(port);
        }
        else {
            UNREACHABLE();
        }

        CHECK(0 == sockaddr_to_str(&s.addr, &address));

        /* tcp bind */
        ENSURE((tcp_handle = malloc(sizeof(*tcp_handle))) != NULL);
        CHECK(0 == uv_tcp_init(loop, tcp_handle));

        ret = uv_tcp_bind(tcp_handle, &s.addr, 0);
        if ( 0 != ret ) {
            ssnetio_on_msg(
                1,
                "tcp bind to %s:%d failed: %s",
                address.host,
                address.port,
                uv_strerror(ret));
            BREAK_NOW;
        }

        ret = uv_listen((uv_stream_t *)tcp_handle, SOMAXCONN, on_connection);
        if ( 0 != ret ) {
            ssnetio_on_msg(
                1,
                "tcp listen to %s:%d failed: %s",
                address.host,
                address.port,
                uv_strerror(ret));
            BREAK_NOW;
        }

        /* udp bind */
        ENSURE((udp_handle = malloc(sizeof(*udp_handle))) != NULL);
        CHECK(0 == uv_udp_init(loop, udp_handle));

        /* associate buf to handle */
        ENSURE((ss_buf = malloc(sizeof(*ss_buf))) != NULL);
        ENSURE((ss_buf->buf_base = malloc(MAX_SS_UDP_FRAME_LEN)) != NULL);
        ss_buf->data_base = ss_buf->buf_base;
        ss_buf->buf_len = MAX_SS_UDP_FRAME_LEN;
        uv_handle_set_data((uv_handle_t*)udp_handle, ss_buf);

        ret = uv_udp_bind(udp_handle, &s.addr, 0);
        if ( 0 != ret ) {
            ssnetio_on_msg(
                1,
                "udp bind to %s:%d failed: %s",
                address.host,
                address.port,
                uv_strerror(ret));
            BREAK_NOW;
        }
        CHECK(0 == dgram_read_local(udp_handle));


        /* dns bind */
        sockaddr_set_port(&s.addr, dns_port);
        ret = dns_server_launch(loop, &s.addr);
        if ( 0 != ret ) {
            ssnetio_on_msg(
                1,
                "dns bind to %s:%d failed: %s",
                address.host,
                dns_port,
                uv_strerror(ret));
            BREAK_NOW;
        }

        ssnetio_on_bind(address.host, address.port);
    }

BREAK_LABEL:

    if ( addrs )
        uv_freeaddrinfo(addrs);

    if ( 0 != ret )
        loop_walk_clear(loop);
}

void on_connection(uv_stream_t *server, int status) {
    static unsigned int index = 0;
    uv_loop_t *loop;
    PROXY_NODE *pn;
    CONN *incoming;
    CONN *outgoing;

    BREAK_ON_FALSE(0 == status);

    loop = uv_handle_get_loop((uv_handle_t *)server);

    ENSURE((pn = malloc(sizeof(*pn))) != NULL);
    memset(pn, 0, sizeof(*pn));

    pn->state = s_handshake;
    pn->outstanding = 0;
    pn->index = index++;
    pn->loop = loop;
    pn->ctx = NULL;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    CHECK(0 == uv_tcp_init(loop, &incoming->handle.tcp));
    CHECK(0 == uv_accept(server, &incoming->handle.stream));
    uv_handle_set_data(&incoming->handle.handle, incoming);
    incoming->pn = pn;
    incoming->result = 0;
    incoming->rdstate = c_stop;
    incoming->wrstate = c_stop;
    incoming->idle_timeout = srv_ctx.config.idel_timeout;
    CHECK(0 == uv_timer_init(loop, &incoming->timer_handle));

    CHECK(0 == uv_tcp_init(loop, &outgoing->handle.tcp));
    uv_handle_set_data(&outgoing->handle.handle, outgoing);
    outgoing->pn = pn;
    outgoing->result = 0;
    outgoing->rdstate = c_stop;
    outgoing->wrstate = c_stop;
    outgoing->idle_timeout = srv_ctx.config.idel_timeout;
    CHECK(0 == uv_timer_init(loop, &outgoing->timer_handle));

    incoming->ss_buf.buf_base = incoming->ss_buf.data_base = incoming->t.slab;
    incoming->ss_buf.buf_len = sizeof(incoming->t.slab);
    incoming->ss_buf.data_len = 0;
    outgoing->ss_buf.buf_base = outgoing->ss_buf.data_base = outgoing->t.slab;
    outgoing->ss_buf.buf_len = sizeof(outgoing->t.slab);
    outgoing->ss_buf.data_len = 0;

    CHECK(0 == str_tcp_endpoint(&incoming->handle.tcp, peer, &incoming->peer));
    /* Emit a notify */
    ssnetio_on_new_stream(incoming);

    /* Wait for the initial packet. */
    conn_read(incoming);

BREAK_LABEL:

    return;
}

void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    CONN *conn;

    (void)size;

    conn = uv_handle_get_data(handle);

    buf->base = conn->ss_buf.buf_base;

    if ( conn == &conn->pn->outgoing ) {
        buf->len = MAX_SS_TCP_PAYLOAD_LEN;
    } else {
        buf->len = conn->ss_buf.buf_len;
    }
}

void conn_read(CONN *conn) {
    ASSERT(conn->rdstate == c_stop);

    if( 0 != uv_read_start(
        &conn->handle.stream,
        conn_alloc,
        conn_read_done) ) {

        do_kill(conn->pn);
        BREAK_NOW;
    }
    conn->rdstate = c_busy;
    conn_timer_reset(conn);

BREAK_LABEL:

    return;
}

void conn_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    CONN *conn;

    conn = uv_handle_get_data((uv_handle_t*)handle);
    ASSERT(conn->ss_buf.buf_base == buf->base);
    ASSERT(c_busy == conn->rdstate);
    conn->rdstate = c_done;
    conn->result = nread;

    uv_read_stop(&conn->handle.stream);
    do_next(conn);
}

void conn_write(CONN *conn, const void *data, unsigned int len) {
    uv_buf_t buf;

    ASSERT(c_stop == conn->wrstate || c_done == conn->wrstate);
    conn->wrstate = c_busy;

    buf = uv_buf_init((char*)data, len);

    if ( 0 != uv_write(&conn->write_req,
                       &conn->handle.stream,
                       &buf,
                       1,
                       conn_write_done) ) {
        do_kill(conn->pn);
        BREAK_NOW;
    }
    conn->pn->outstanding++;
    conn_timer_reset(conn);

BREAK_LABEL:

    return;
}

void conn_write_done(uv_write_t *req, int status) {
    CONN *conn;

    conn = CONTAINER_OF(req, CONN, write_req);
    conn->pn->outstanding--;
    ASSERT(c_busy == conn->wrstate);
    conn->wrstate = c_done;
    conn->result = status;

    do_next(conn);
}

void conn_connect_done(uv_connect_t *req, int status) {
    CONN *conn;

    conn = CONTAINER_OF(req, CONN, t.connect_req);
    conn->result = status;

    conn->pn->outstanding--;
    do_next(conn);
}

void conn_close(CONN *conn) {
    ASSERT(c_dead != conn->rdstate);
    ASSERT(c_dead != conn->wrstate);
    conn->rdstate = c_dead;
    conn->wrstate = c_dead;
    uv_handle_set_data((uv_handle_t*)&conn->timer_handle, conn);
    uv_handle_set_data(&conn->handle.handle, conn);
    uv_close(&conn->handle.handle, conn_close_done);
    uv_close((uv_handle_t*)&conn->timer_handle, conn_close_done);
}

void conn_close_done(uv_handle_t *handle) {
    CONN *conn;

    conn = uv_handle_get_data(handle);
    do_next(conn);
}

void conn_timer_reset(CONN *conn) {
    CHECK(0 == uv_timer_start(&conn->timer_handle,
                              conn_timer_expire,
                              conn->idle_timeout,
                              0));
}

int conn_cycle(const char *who, CONN *a, CONN *b) {
    if ( a->result < 0 ) {
        if ( UV_EOF != a->result ) {
            ssnetio_on_msg(
                1,
                "%4d %s error: %s [%s]",
                a->pn->index,
                who,
                uv_strerror((int)a->result),
                a->pn->link_info);
        }

        return -1;
    }

    if ( b->result < 0 ) {
        return -1;
    }

    if ( c_done == a->wrstate ) {
        a->wrstate = c_stop;
    }

    /* The logic is as follows: read when we don't write and write when we don't
     * read.  That gives us back-pressure handling for free because if the peer
     * sends data faster than we consume it, TCP congestion control kicks in.
     */
    if ( c_stop == a->wrstate ) {
        if ( c_stop == b->rdstate ) {
            conn_read(b);
        }
        else if ( c_done == b->rdstate ) {
            conn_write(a, b->ss_buf.data_base, (unsigned int)b->ss_buf.data_len);
            b->rdstate = c_stop;  /* Triggers the call to conn_read() above. */
        }
    }

    return 0;
}

int do_proxy_start(PROXY_NODE *pn) {
    CONN *incoming;
    CONN *outgoing;
    int new_state;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( outgoing->result < 0 ) {
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_stop == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    ASSERT(c_stop == outgoing->rdstate);
    ASSERT(c_done == outgoing->wrstate);
    outgoing->wrstate = c_stop;

    conn_read(incoming);
    conn_read(outgoing);

    new_state = s_proxy;

BREAK_LABEL:

    return new_state;
}

int do_proxy(CONN *sender) {
    int new_state = s_proxy, encrypt = 0, action;
    CONN *incoming;
    CONN *outgoing;

    incoming = &sender->pn->incoming;
    outgoing = &sender->pn->outgoing;

    if ( c_done == sender->rdstate && sender->result >= 0 ) {
        encrypt = sender == outgoing;

        if ( encrypt ) {
            sender->ss_buf.data_len = (size_t)sender->result;
            action = ssnetio_on_plain_stream(sender);
            switch (action) {
            case PASS:
                break;

            case NEEDMORE:
            case REJECT:
                BREAK_NOW;

            case TERMINATE:
                new_state = do_kill(incoming->pn);
                BREAK_NOW;
            default:
                UNREACHABLE();
            }

            if ( 0 != ssnetio_on_stream_encrypt(sender, 0) ) {
                new_state = do_kill(incoming->pn);
                BREAK_NOW;
            }
        } else {
            if ( 0 != ssnetio_on_stream_decrypt(sender, 0) ) {
                new_state = do_kill(incoming->pn);
                BREAK_NOW;
            }

            action = ssnetio_on_plain_stream(sender);
            switch (action) {
            case PASS:
                break;

            case NEEDMORE:
            case REJECT:
                BREAK_NOW;

            case TERMINATE:
                new_state = do_kill(incoming->pn);
                BREAK_NOW;
            default:
                UNREACHABLE();
            }
        }
    }

    if ( 0 != conn_cycle("client", incoming, outgoing) ) {
        new_state = do_kill(incoming->pn);
        BREAK_NOW;
    }

    if ( 0 != conn_cycle("upstream", outgoing, incoming) ) {
        new_state = do_kill(incoming->pn);
        BREAK_NOW;
    }

BREAK_LABEL:

    return new_state;
}

int do_kill(PROXY_NODE *pn) {
    int new_state;

    if ( 0 != pn->outstanding ) {
        /* Wait for uncomplete operations */
        ssnetio_on_msg(
            4,
            "%4d Waitting outstanding operation: %d [%s]",
            pn->index, pn->outstanding, pn->link_info);
        new_state = s_kill;
        BREAK_NOW;
    }

    if ( pn->state >= s_almost_dead_0 ) {
        new_state = pn->state;
        BREAK_NOW;
    }

    conn_close(&pn->incoming);
    conn_close(&pn->outgoing);

    new_state = s_almost_dead_1;

BREAK_LABEL:

    return new_state;
}

int do_almost_dead(PROXY_NODE *pn) {
    ASSERT(pn->state >= s_almost_dead_0);
    return pn->state + 1;  /* Another finalizer completed. */
}

int do_clear(PROXY_NODE *pn) {
    ssnetio_on_stream_teardown(pn);

    if ( DEBUG_CHECKS ) {
        memset(pn, -1, sizeof(*pn));
    }
    free(pn);

    return 0;
}

static void conn_timer_expire(uv_timer_t *handle) {
    conn_timer_expire_server(handle);
}

static void do_next(CONN *sender) {
    do_next_server(sender);
}

static void loop_walk_clear(uv_loop_t *loop) {
    uv_walk(loop, loop_walk_cb, NULL);
}

static void loop_walk_cb(uv_handle_t* handle, void* arg) {
    uv_handle_type type;
    SSNETIO_BUF *ss_buf;

    (void)arg;

    type = uv_handle_get_type(handle);
    if ( UV_TCP == type ) {
        uv_close(handle, loop_walk_close_done);
    } else if ( UV_UDP == type ) {
        ss_buf = uv_handle_get_data(handle);

        if ( ss_buf ) {
            ASSERT(ss_buf->buf_base);
            free(ss_buf->buf_base);
            free(ss_buf);
        }

        uv_close(handle, loop_walk_close_done);
    } else {
        uv_close(handle, NULL);
    }
}

static void loop_walk_close_done(uv_handle_t* handle) {
    free(handle);
}
