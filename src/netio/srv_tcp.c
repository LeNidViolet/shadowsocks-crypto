/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2019-07-04.
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
#include "internal.h"
#include "shadowsocks-crypto/shadowsocks-crypto.h"
#include "dns_cache.h"
#include "udns/parsedns.h"

// ==========
#define tcp_handle_max 8
static int tcp_handle_index = 0;
static uv_tcp_t *tcp_handles[tcp_handle_max] = { NULL };

static uv_signal_t tcp_signal_handle;
static int tcp_signal_inited = 0;

static int pn_outstanding = 0;

static void on_connection(uv_stream_t *server, int status);


static void tcpsrv_signal_cb(uv_signal_t* handle, int signum) {
    (void)handle;
    (void)signum;

    server_tcp_stop();
}

/* 注册信号 */
static int tcpsrv_signal_setup(uv_loop_t *loop) {
    int ret;

    if ( tcp_signal_inited ) {
        ret = 0;
        BREAK_NOW;
    }

    ret = uv_signal_init(loop, &tcp_signal_handle);
    CHECK(0 == ret);

    uv_signal_start(&tcp_signal_handle, tcpsrv_signal_cb, SIGINT);
    uv_signal_start(&tcp_signal_handle, tcpsrv_signal_cb, SIGTERM);

    tcp_signal_inited = 1;
BREAK_LABEL:

    return ret;
}

static void tcpsrv_signal_close_done(uv_handle_t* handle) {
    (void)handle;
}

static void tcpsrv_signal_close() {
    if ( tcp_signal_inited ) {
        uv_signal_stop(&tcp_signal_handle);
        uv_close((uv_handle_t*)&tcp_signal_handle, tcpsrv_signal_close_done);
        tcp_signal_inited = 0;
    }
}

static void tcpsrv_handle_close_done(uv_handle_t* handle) {
    if ( handle ) {
        free(handle);
    }
}

static void tcpsrv_handle_close(uv_tcp_t *handle) {
    if ( handle ) {
        // TODO: tcp 句柄更多清理
        uv_close((uv_handle_t*)handle, tcpsrv_handle_close_done);
    }
}

/* 启动 TCP 服务 */
int server_tcp_launch(uv_loop_t *loop, const struct sockaddr *addr) {
    int ret = -1;
    uv_tcp_t *tcp_handle = NULL;
    address address = {0};

    BREAK_ON_NULL(loop);
    BREAK_ON_NULL(addr);

    if ( tcp_handle_index >= tcp_handle_max ) BREAK_NOW;

    CHECK(0 == sockaddr_to_str(addr, &address, 1));

    ENSURE((tcp_handle = malloc(sizeof(*tcp_handle))) != NULL);
    CHECK(0 == uv_tcp_init(loop, tcp_handle));

    ret = uv_tcp_bind(tcp_handle, addr, 0);
    if ( 0 != ret ) {
        ssnetio_on_msg(
            LOG_ERROR,
            "tcp bind to %s:%d failed: %s",
            address.ip,
            address.port,
            uv_strerror(ret));
        BREAK_NOW;
    }

    ret = uv_listen((uv_stream_t *)tcp_handle, SOMAXCONN, on_connection);
    if ( 0 != ret ) {
        ssnetio_on_msg(
            LOG_ERROR,
            "tcp listen to %s:%d failed: %s",
            address.ip,
            address.port,
            uv_strerror(ret));
        BREAK_NOW;
    }

    tcp_handles[tcp_handle_index++] = tcp_handle;
    tcp_handle = NULL;

    tcpsrv_signal_setup(loop);

BREAK_LABEL:

    if ( tcp_handle ) {
        tcpsrv_handle_close(tcp_handle);
    }

    return ret;
}

void server_tcp_stop() {

    for ( int i = 0; i < tcp_handle_max; ++i ) {
        if ( tcp_handles[i] ) {
            tcpsrv_handle_close(tcp_handles[i]);
        }
    }

    memset(tcp_handles, 0, sizeof(tcp_handles));
    tcp_handle_index = 0;

    tcpsrv_signal_close();
    ssnetio_on_msg(LOG_KEY, "tcp server exited");
}




// ===========
// ===========
extern sscrypto_ctx srv_ctx;
static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void conn_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void conn_timer_expire(uv_timer_t *handle);
static void conn_write(connection *conn, const void *data, unsigned int len);
static void conn_write_done(uv_write_t *req, int status);
static void conn_connect_done(uv_connect_t *req, int status);
static void conn_close(connection *conn);
static void conn_close_done(uv_handle_t *handle);
static int  conn_cycle(const char *who, connection *a, connection *b);
static void conn_timer_expire_server(uv_timer_t *handle);
static void conn_getaddrinfo_done(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);

static void do_next(connection *sender);
static int  do_proxy_start(proxy_node *pn);
static int  do_proxy(connection *sender);
static int  do_almost_dead(proxy_node *pn);
static int  do_clear(proxy_node *pn);
static void do_next_server(connection *sender);

static int  do_handshake(proxy_node *pn);
static int  do_req_lookup(proxy_node *pn);
static int  do_dnsovertcp_lookup(proxy_node *pn);
static void do_dnsovertcp_packback(proxy_node *pn, struct sockaddr *addr);
static int  do_req_connect(proxy_node *pn);

/* 入口点 代理链接到来 */
static void on_connection(uv_stream_t *server, int status) {
    static unsigned int index = 0;
    uv_loop_t *loop;
    proxy_node *pn;
    connection *incoming;
    connection *outgoing;

    BREAK_ON_FALSE(0 == status);

    loop = uv_handle_get_loop((uv_handle_t *)server);

    ENSURE((pn = malloc(sizeof(*pn))) != NULL);
    memset(pn, 0, sizeof(*pn));

    pn_outstanding++;

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

    incoming->ss_buf.buf_base = incoming->ss_buf.data_base = incoming->slab;
    incoming->ss_buf.buf_len = sizeof(incoming->slab);
    incoming->ss_buf.data_len = 0;

    outgoing->ss_buf.buf_base = outgoing->ss_buf.data_base = outgoing->slab;
    outgoing->ss_buf.buf_len = sizeof(outgoing->slab);
    outgoing->ss_buf.data_len = 0;

    // 设置 incoming.peer.ip
    CHECK(0 == str_tcp_endpoint(&incoming->handle.tcp, peer, &incoming->peer));

    // incoming.peer.ip 是 ip 字符串, 拷贝到domain中
    strcpy(incoming->peer.domain, incoming->peer.ip);

    /* Emit a notify */
    ssnetio_on_new_stream(incoming);

    /* Wait for the initial packet. */
    conn_read(incoming);

BREAK_LABEL:

    return;
}

static void conn_alloc(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    connection *conn;

    (void)size;

    conn = uv_handle_get_data(handle);

    buf->base = conn->ss_buf.buf_base;

    if ( conn == &conn->pn->outgoing ) {
        buf->len = MAX_SS_TCP_PAYLOAD_LEN;
    } else {
        buf->len = conn->ss_buf.buf_len;
    }
}

void conn_read(connection *conn) {
    ASSERT(c_stop == conn->rdstate);

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

static void conn_read_done(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    connection *conn;

    conn = uv_handle_get_data((uv_handle_t*)handle);
    ASSERT(conn->ss_buf.buf_base == buf->base);
    ASSERT(c_busy == conn->rdstate);
    conn->rdstate = c_done;
    conn->result = nread;

    uv_read_stop(&conn->handle.stream);
    do_next(conn);
}

static void conn_write(connection *conn, const void *data, unsigned int len) {
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

static void conn_write_done(uv_write_t *req, int status) {
    connection *conn;

    conn = CONTAINER_OF(req, connection, write_req);
    conn->pn->outstanding--;
    ASSERT(c_busy == conn->wrstate);
    conn->wrstate = c_done;
    conn->result = status;

    do_next(conn);
}

static void conn_connect_done(uv_connect_t *req, int status) {
    connection *conn;

    conn = CONTAINER_OF(req, connection, t.connect_req);
    conn->result = status;

    conn->pn->outstanding--;
    do_next(conn);
}

static void conn_close(connection *conn) {
    ASSERT(c_dead != conn->rdstate);
    ASSERT(c_dead != conn->wrstate);
    conn->rdstate = c_dead;
    conn->wrstate = c_dead;
    uv_handle_set_data((uv_handle_t*)&conn->timer_handle, conn);
    uv_handle_set_data(&conn->handle.handle, conn);
    uv_close(&conn->handle.handle, conn_close_done);
    uv_close((uv_handle_t*)&conn->timer_handle, conn_close_done);
}

static void conn_close_done(uv_handle_t *handle) {
    connection *conn;

    conn = uv_handle_get_data(handle);
    do_next(conn);
}

void conn_timer_reset(connection *conn) {
    CHECK(0 == uv_timer_start(&conn->timer_handle,
                              conn_timer_expire,
                              conn->idle_timeout,
                              0));
}

static void conn_timer_expire(uv_timer_t *handle) {
    conn_timer_expire_server(handle);
}

static void conn_timer_expire_server(uv_timer_t *handle) {
    connection *conn;
    connection *incoming;
    connection *outgoing;

    conn = CONTAINER_OF(handle, connection, timer_handle);

    incoming = &conn->pn->incoming;
    outgoing = &conn->pn->outgoing;

    switch ( conn->pn->state ) {
    case s_handshake:
        ASSERT(conn == incoming);
        incoming->result = UV_ETIMEDOUT;
        break;
    case s_req_lookup:
    case s_dnsovertcp_lookup:
    case s_req_connect:
    case s_proxy_start:
        outgoing->result = UV_ETIMEDOUT;
        break;
    default:
        conn->result = UV_ETIMEDOUT; /* s_proxy, .. */
        break;
    }

    do_next_server(conn);
}

static int conn_cycle(const char *who, connection *a, connection *b) {
    if ( a->result < 0 ) {
        if ( UV_EOF != a->result ) {
            ssnetio_on_msg(
                LOG_WARN,
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


// ==========
static int do_proxy_start(proxy_node *pn) {
    connection *incoming;
    connection *outgoing;
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

static int do_proxy(connection *sender) {
    int new_state = s_proxy, encrypt = 0, action;
    connection *incoming;
    connection *outgoing;

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

int do_kill(proxy_node *pn) {
    int new_state;

    if ( 0 != pn->outstanding ) {
        /* Wait for uncomplete operations */
        ssnetio_on_msg(
            LOG_INFO,
            "%4d waitting outstanding operation: %d [%s]",
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

static int do_almost_dead(proxy_node *pn) {
    ASSERT(pn->state >= s_almost_dead_0);
    return pn->state + 1;  /* Another finalizer completed. */
}

static int do_clear(proxy_node *pn) {
    ssnetio_on_stream_teardown(pn);

    if ( DEBUG_CHECKS ) {
        memset(pn, -1, sizeof(*pn));
    }
    free(pn);
    pn_outstanding--;

    if ( 0 == pn_outstanding )
        ssnetio_on_msg(LOG_INFO, "pn outstanding return to 0");

    return 0;
}

static void do_next(connection *sender) {
    do_next_server(sender);
}


static void conn_getaddrinfo_done(
    uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    connection *incoming;
    connection *outgoing;
    struct addrinfo *ai;
    struct addrinfo *ai_ipv4 = NULL;
    struct addrinfo *ai_ipv6 = NULL;

    outgoing = CONTAINER_OF(req, connection, t.addrinfo_req);
    ASSERT(outgoing == &outgoing->pn->outgoing);
    outgoing->result = status;

    incoming = &outgoing->pn->incoming;

    if ( 0 == status ) {
        for ( ai = addrs; ai != NULL; ai = ai->ai_next ) {
            dns_cache_add(outgoing->peer.domain, ai->ai_addr);

            if ( AF_INET == ai->ai_family && !ai_ipv4 ) {
                ai_ipv4 = ai;
            }
            if ( AF_INET6 == ai->ai_family && !ai_ipv6 ) {
                ai_ipv6 = ai;
            }
        }

        sockaddr_cpy(ai_ipv4 ? ai_ipv4->ai_addr : addrs->ai_addr, &outgoing->t.addr);
        sockaddr_set_port(&outgoing->t.addr, outgoing->peer.port);

        /* 设置UPSTREAM远端 IP信息 */
        sockaddr_to_str(&outgoing->t.addr, &outgoing->peer, 0);
    }

    uv_freeaddrinfo(addrs);

    incoming->pn->outstanding--;
    do_next_server(incoming);
}


static void do_next_server(connection *sender) {
    int new_state = s_max;
    proxy_node *pn = sender->pn;

    ASSERT(s_dead != pn->state);
    switch (pn->state) {
    case s_handshake:
        new_state = do_handshake(pn);
        break;
    case s_req_lookup:
        new_state = do_req_lookup(pn);
        break;
    case s_dnsovertcp_lookup:
        new_state = do_dnsovertcp_lookup(pn);
        break;
    case s_req_connect:
        new_state = do_req_connect(pn);
        break;
    case s_proxy_start:
        new_state = do_proxy_start(pn);
        break;
    case s_proxy:
        new_state = do_proxy(sender);
        break;
    case s_kill:
        new_state = do_kill(pn);
        break;
    case s_almost_dead_0:
    case s_almost_dead_1:
    case s_almost_dead_2:
    case s_almost_dead_3:
    case s_almost_dead_4:
        new_state = do_almost_dead(pn);
        break;
    default:
        UNREACHABLE();
    }
    pn->state = new_state;

    if ( s_dead == pn->state )
        do_clear(pn);
}

static int do_dnsovertcp(proxy_node *pn) {
    connection *incoming;
    connection *outgoing;
    int new_state;
    struct addrinfo hints;
    PDNS_PARSE parse = NULL;
    union{
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } addru;
    struct sockaddr *addrp;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;
    assert(0 != incoming->ss_buf.data_len);

    // DNS OVER TCP 前两字节指示包长
    parse = ParseDnsRecord(
        incoming->ss_buf.data_base + 2,
        (unsigned int)incoming->ss_buf.data_len - 2);
    if ( parse ) {

        // IP 格式 字符串?
        if ( 0 == uv_ip4_addr(parse->queryDomain, 53, &addru.addr4) ||
             0 == uv_ip6_addr(parse->queryDomain, 53, &addru.addr6)) {
            // TODO: IPV4 ONLY FOR NOW
            ASSERT(parse->queryType == DNS_QUERY_TYPE_IPV4);

            do_dnsovertcp_packback(pn, &addru.addr);
            new_state = s_kill;
            BREAK_NOW;
        }

        addrp = dns_cache_find_ip(parse->queryDomain, 1);
        if ( addrp ) {
            // 存在于DNS缓存之中
            // TODO: IPV4 ONLY FOR NOW
            ASSERT(parse->queryType == DNS_QUERY_TYPE_IPV4);

            do_dnsovertcp_packback(pn, addrp);
            new_state = s_kill;
        } else {
            // 准备查询DNS
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            // 保存域名信息
            strcpy(pn->outgoing.peer.domain, parse->queryDomain);

            if ( 0 != uv_getaddrinfo(pn->loop,
                                     &outgoing->t.addrinfo_req,
                                     conn_getaddrinfo_done,
                                     parse->queryDomain,
                                     NULL,
                                     &hints) ) {
                new_state = do_kill(pn);
                BREAK_NOW;
            }

            pn->outstanding++;
            conn_timer_reset(outgoing);

            new_state = s_dnsovertcp_lookup;
        }
    } else {
        new_state = do_kill(pn);
    }

BREAK_LABEL:
    if ( parse )
        free(parse);

    return new_state;
}


static int do_handshake(proxy_node *pn) {
    connection *incoming;
    connection *outgoing;
    int ret, new_state;
    struct addrinfo hints;
    const char *host;
    struct sockaddr* addr;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( incoming->result < 0 ) {
        ssnetio_on_msg(LOG_WARN, "%4d handshake read error: %s",
                       pn->index, uv_strerror((int)incoming->result));
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_done == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    incoming->rdstate = c_stop;

    if ( 0 != ssnetio_on_stream_decrypt(incoming, 0) ) {
        ssnetio_on_msg(LOG_WARN, "%4d handshake data decrypt failed", pn->index);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    /* Parser to get dest address  解析之后填充 outgoing.peer.domain */
    ret = s5_parse_addr(&incoming->ss_buf, &outgoing->peer);
    if ( 0 != ret ) {
        ssnetio_on_msg(LOG_WARN, "%4d handshake parse addr error", pn->index);
        new_state = do_kill(pn);
        BREAK_NOW;
    }

    // 接管DNS查询
    if ( 53 == outgoing->peer.port ) {
        new_state = do_dnsovertcp(pn);
        BREAK_NOW;
    }

    /* Maybe it's a ip address in string form */
    if ( 0 == uv_ip4_addr(outgoing->peer.domain, outgoing->peer.port, &outgoing->t.addr4) ||
         0 == uv_ip6_addr(outgoing->peer.domain, outgoing->peer.port, &outgoing->t.addr6)) {

        // 拷贝到 outgoing.peer.ip
        strcpy(outgoing->peer.ip, outgoing->peer.domain);

        host = dns_cache_find_host(&outgoing->t.addr);
        if ( host ) {
            memset(outgoing->peer.domain, 0, sizeof(outgoing->peer.domain));
            strcpy(outgoing->peer.domain, host);
        }

        new_state = do_req_lookup(pn);
        BREAK_NOW;
    }

    addr = dns_cache_find_ip(outgoing->peer.domain, 1);
    if ( !addr ) {
        addr = dns_cache_find_ip(outgoing->peer.domain, 0);
    }
    if ( addr ) {
        // 拷贝到 outgoing.peer.ip
        sockaddr_to_str(addr, &outgoing->peer, 0);

        sockaddr_cpy(addr, &outgoing->t.addr);
        sockaddr_set_port(&outgoing->t.addr, outgoing->peer.port);
        new_state = do_req_lookup(pn);

    } else {
        // 进行DNS查询
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if ( 0 != uv_getaddrinfo(pn->loop,
                                 &outgoing->t.addrinfo_req,
                                 conn_getaddrinfo_done,
                                 outgoing->peer.domain,
                                 NULL,
                                 &hints) ) {
            new_state = do_kill(pn);
            BREAK_NOW;
        }

        pn->outstanding++;
        conn_timer_reset(outgoing);

        new_state = s_req_lookup;
    }

BREAK_LABEL:

    return new_state;
}

static int do_req_lookup(proxy_node *pn) {
    connection *incoming;
    connection *outgoing;
    int ret;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( outgoing->result < 0 ) {
        ssnetio_on_msg(LOG_WARN, "%4d lookup error for %s : %s",
                       pn->index,
                       outgoing->peer.domain,
                       uv_strerror((int)outgoing->result));

        ret = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_stop == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    ASSERT(c_stop == outgoing->rdstate);
    ASSERT(c_stop == outgoing->wrstate);

    ASSERT(AF_INET == outgoing->t.addr.sa_family ||
           AF_INET6 == outgoing->t.addr.sa_family);

    if ( 0 != uv_tcp_connect(&outgoing->t.connect_req,
                             &outgoing->handle.tcp,
                             &outgoing->t.addr,
                             conn_connect_done) ) {
        ret = do_kill(pn);
        BREAK_NOW;
    }

    pn->outstanding++;
    conn_timer_reset(outgoing);

    ret = s_req_connect;

BREAK_LABEL:

    return ret;
}


static void do_dnsovertcp_packback(proxy_node *pn, struct sockaddr *addr) {
    connection *incoming = &pn->incoming;
    struct sockaddr_in *addr_v4 = (struct sockaddr_in *)addr;
    unsigned short pkt_len;

    // TODO: 组包回发
    pkt_len = ByteswapUshort(*(unsigned short*)incoming->ss_buf.data_base);
    PDNS_HEADER hdr = (PDNS_HEADER)(incoming->ss_buf.data_base + 2);
    hdr->IsResponse = 1;
    hdr->RecursionAvailable = 1;
    hdr->AnswerCount = ByteswapUshort(1);

    char* pos = incoming->ss_buf.data_base + pkt_len;
    *(unsigned short*)pos = 0x0CC0;
    pos += 2;

    PDNS_WIRE_RECORD record = (PDNS_WIRE_RECORD)pos;
    // TODO: IPV4 ONLY FOR NOW
    record->RecordType  = ByteswapUshort(1);
    record->RecordClass = ByteswapUshort(1); // CLASS IN
    record->TimeToLive  = ByteswapUInt32(10);
    // TODO: IPV4 ONLY FOR NOW
    record->DataLength  = ByteswapUshort(4);

    pos = (char*)(record + 1);
    *(unsigned int*)pos = addr_v4->sin_addr.s_addr;

    // TODO: IPV4 ONLY FOR NOW
    pkt_len += 2 + sizeof(DNS_WIRE_RECORD) + 4;
    *(unsigned short*)incoming->ss_buf.data_base = ByteswapUshort(pkt_len);

    incoming->ss_buf.data_len = pkt_len + 2;

    conn_write(
        incoming,
        incoming->ss_buf.data_base,
        (unsigned int)incoming->ss_buf.data_len);
}

static int do_dnsovertcp_lookup(proxy_node *pn) {
    connection *incoming;
    connection *outgoing;
    int ret;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( outgoing->result < 0 ) {
        ssnetio_on_msg(LOG_WARN, "%4d lookup error for %s : %s",
                       pn->index,
                       outgoing->peer.domain,
                       uv_strerror((int)outgoing->result));

        ret = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_stop == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    ASSERT(c_stop == outgoing->rdstate);
    ASSERT(c_stop == outgoing->wrstate);

    ASSERT(AF_INET == outgoing->t.addr.sa_family ||
           AF_INET6 == outgoing->t.addr.sa_family);


    do_dnsovertcp_packback(pn, &outgoing->t.addr);
    ret = s_kill;

BREAK_LABEL:

    return ret;
}


static int do_req_connect(proxy_node *pn) {
    connection *incoming;
    connection *outgoing;
    int ret, action;

    incoming = &pn->incoming;
    outgoing = &pn->outgoing;

    if ( 0 != outgoing->result ) {
        ssnetio_on_msg(
            LOG_WARN,
            "%4d connect to %s:%d failed: %s",
            pn->index,
            outgoing->peer.domain,
            outgoing->peer.port,
            uv_strerror((int)outgoing->result));
        ret = do_kill(pn);
        BREAK_NOW;
    }

    ASSERT(c_stop == incoming->rdstate);
    ASSERT(c_stop == incoming->wrstate);
    ASSERT(c_stop == outgoing->rdstate);
    ASSERT(c_stop == outgoing->wrstate);

    ssnetio_on_connection_made(pn);

    snprintf(pn->link_info, sizeof(pn->link_info), "%s:%d -> %s:%d",
             incoming->peer.domain,
             incoming->peer.port,
             outgoing->peer.domain,
             outgoing->peer.port);

    if ( 0 == incoming->ss_buf.data_len ) {
        conn_read(incoming);
        conn_read(outgoing);
        ret = s_proxy;
    } else {
        action = ssnetio_on_plain_stream(incoming);
        switch (action) {
        case PASS:
            break;

        case NEEDMORE:
        case REJECT:
            ret = s_proxy;
            BREAK_NOW;

        case TERMINATE:
            ret = do_kill(pn);
            BREAK_NOW;
        default:
            UNREACHABLE();
        }

        conn_write(
            outgoing,
            incoming->ss_buf.data_base,
            (unsigned int)incoming->ss_buf.data_len);
        ret = s_proxy_start;
    }

BREAK_LABEL:

    return ret;
}
