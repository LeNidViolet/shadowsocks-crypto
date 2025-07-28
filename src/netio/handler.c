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
#include "internal.h"

// ==========
void sscrypto_on_msg(int level, const char *format, ...);
void sscrypto_on_bind(const char *host, unsigned short port);
void sscrypto_on_stream_connection_made(address_pair *addr, void *ctx);
void sscrypto_on_new_stream(const ADDRESS *addr, void **ctx, void *stream_id);
void sscrypto_on_stream_teardown(void *ctx);
void sscrypto_on_new_dgram(const address_pair *addr, void **ctx);
void sscrypto_on_dgram_teardown(void *ctx);
int  sscrypto_on_plain_stream(const BUF_RANGE *buf, int direct, void *ctx);
void sscrypto_on_plain_dgram(const BUF_RANGE *buf, int direct, void *ctx);
int  sscrypto_on_stream_encrypt(BUF_RANGE *buf, void *ctx);
int  sscrypto_on_stream_decrypt(BUF_RANGE *buf, void *ctx);
int  sscrypto_on_dgram_encrypt(BUF_RANGE *buf);
int  sscrypto_on_dgram_decrypt(BUF_RANGE *buf);


// ==========

typedef struct {
    BUF_RANGE   buf;
    uv_write_t  req;
    CONN  *conn;
} snd_ctx;

static void ssnetio_write_stream_out_done(uv_write_t *req, int status);

// ReSharper disable once CppParameterMayBeConst
void ssnetio_on_msg(int level, const char *format, ...) {
    va_list ap;
    char msg[1024];

    va_start(ap, format);
    vsnprintf(msg, sizeof(msg), format, ap);
    va_end(ap);

    sscrypto_on_msg(level, msg);
}

// ReSharper disable once CppParameterMayBeConst
void ssnetio_on_bind(const char *host, unsigned short port) {
    sscrypto_on_bind(host, port);
}

void ssnetio_on_connection_made(PROXY_NODE *pn) {
    address_pair pair;

    pair.local = &pn->incoming.peer;
    pair.remote = &pn->outgoing.peer;

    sscrypto_on_stream_connection_made(&pair, pn->ctx);
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
void ssnetio_on_new_stream(CONN *conn) {
    void *ctx = NULL;

    sscrypto_on_new_stream(&conn->peer, &ctx, conn->pn);
    conn->pn->ctx = ctx;
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
void ssnetio_on_stream_teardown(PROXY_NODE *pn) {
    sscrypto_on_stream_teardown(pn->ctx);
}

void ssnetio_on_new_dgram(ADDRESS *local, ADDRESS *remote, void **ctx) {
    address_pair pair;

    pair.local = local;
    pair.remote = remote;

    sscrypto_on_new_dgram(&pair, ctx);
}

void ssnetio_on_dgram_teardown(void *ctx) {
    sscrypto_on_dgram_teardown(ctx);
}

// ReSharper disable once CppParameterMayBeConst
int ssnetio_on_stream_encrypt(CONN *conn, int offset) {
    int ret;
    BUF_RANGE buf;

    buf.buf_base = conn->ss_buf.buf_base;
    buf.buf_len = conn->ss_buf.buf_len;
    buf.data_base = buf.buf_base + offset;
    buf.data_len = (size_t)conn->result - offset;

    conn->ss_buf.data_base = conn->ss_buf.buf_base + offset;
    conn->ss_buf.data_len = (size_t)conn->result - offset;
    ret = sscrypto_on_stream_encrypt(&buf, conn->pn->ctx);

    conn->ss_buf.data_base = buf.data_base;
    conn->ss_buf.data_len = buf.data_len;

    return ret;
}

// ReSharper disable once CppParameterMayBeConst
int ssnetio_on_stream_decrypt(CONN *conn, int offset) {
    int ret;
    BUF_RANGE buf;

    buf.buf_base = conn->ss_buf.buf_base;
    buf.buf_len = conn->ss_buf.buf_len;
    buf.data_base = buf.buf_base + offset;
    buf.data_len = (size_t)conn->result - offset;

    conn->ss_buf.data_base = conn->ss_buf.buf_base + offset;
    conn->ss_buf.data_len = (size_t)conn->result - offset;
    ret = sscrypto_on_stream_decrypt(&buf, conn->pn->ctx);

    conn->ss_buf.data_base = buf.data_base;
    conn->ss_buf.data_len = buf.data_len;

    return ret;
}

// ReSharper disable once CppParameterMayBeConst
int ssnetio_on_dgram_encrypt(BUF_RANGE *buf, int offset) {
    int ret;

    buf->data_base = buf->buf_base + offset;
    buf->data_len = buf->data_len - offset;

    ret = sscrypto_on_dgram_encrypt(buf);

    return ret;
}

// ReSharper disable once CppParameterMayBeConst
int ssnetio_on_dgram_decrypt(BUF_RANGE *buf, int offset) {
    int ret;

    buf->data_base = buf->buf_base + offset;
    buf->data_len = buf->data_len - offset;

    ret = sscrypto_on_dgram_decrypt(buf);

    return ret;
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
int ssnetio_on_plain_stream(CONN *conn) {
    int action;
    const int direct = conn == &conn->pn->incoming ? STREAM_UP : STREAM_DOWN;

    action = sscrypto_on_plain_stream(
        &conn->ss_buf,
        direct,
        conn->pn->ctx);

    return action;
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
void ssnetio_on_plain_dgram(BUF_RANGE *buf, int direct, void *ctx) {

    sscrypto_on_plain_dgram(buf, direct, ctx);
}

/* SERVER SIDE ONLY */
int ssnetio_write_stream_out(
    // ReSharper disable once CppParameterMayBeConst
    const char *buf,  size_t len, int direct, void *stream_id) {
    int ret = -1;
    PROXY_NODE *pn;
    CONN *conn;
    uv_buf_t buf_t;
    snd_ctx *snd_ctx;

    BREAK_ON_NULL(buf);
    BREAK_ON_FALSE(STREAM_UP == direct || STREAM_DOWN == direct);
    BREAK_ON_NULL(stream_id);

    pn = (PROXY_NODE*)stream_id;
    conn = STREAM_UP == direct ? &pn->outgoing : &pn->incoming;


    snd_ctx = malloc(sizeof(*snd_ctx));
    ASSERT(snd_ctx);
    memset(snd_ctx, 0, sizeof(*snd_ctx));

    snd_ctx->buf.buf_base = malloc(len + 64);
    ASSERT(snd_ctx->buf.buf_base);
    snd_ctx->buf.data_base = snd_ctx->buf.buf_base;
    snd_ctx->buf.buf_len = len + 64;
    snd_ctx->buf.data_len = len;
    memmove(snd_ctx->buf.data_base, buf, len);


    if ( STREAM_DOWN == direct ) {
        ret = sscrypto_on_stream_encrypt(&snd_ctx->buf, conn->pn->ctx);
        ASSERT(0 == ret);
        ret = -2;
    }

    buf_t = uv_buf_init(snd_ctx->buf.data_base, snd_ctx->buf.data_len);

    uv_req_set_data((uv_req_t*)&snd_ctx->req, snd_ctx);
    snd_ctx->conn = conn;

    if ( 0 != uv_write(&snd_ctx->req,
                       &conn->handle.stream,
                       &buf_t,
                       1,
                       ssnetio_write_stream_out_done) ) {
        free(snd_ctx);
        do_kill(conn->pn);
        BREAK_NOW;
    }
    conn->pn->outstanding++;
    conn_timer_reset(conn);

    ret = 0;

BREAK_LABEL:

    return ret;
}

static void ssnetio_write_stream_out_done(uv_write_t *req, int status) {
    CONN *conn;
    snd_ctx *snd_ctx;

    snd_ctx = uv_req_get_data((uv_req_t*)req);

    conn = snd_ctx->conn;
    conn->pn->outstanding--;

    if ( snd_ctx->buf.buf_base )
        free(snd_ctx->buf.buf_base);
    free(snd_ctx);
}

// ReSharper disable once CppParameterMayBeConst
void ssnetio_stream_pause(void *stream_id, int direct, int pause) {
    PROXY_NODE *pn;
    CONN *conn;

    BREAK_ON_NULL(stream_id);
    BREAK_ON_FALSE(STREAM_UP == direct || STREAM_DOWN == direct);

    pn = (PROXY_NODE*)stream_id;
    conn = STREAM_UP == direct ? &pn->outgoing : &pn->incoming;
    if ( pause ) {
        if ( c_busy == conn->rdstate )
            uv_read_stop(&conn->handle.stream);
        if ( c_stop != conn->rdstate )
            conn->rdstate = c_stop;
    } else {
        if ( c_busy != conn->rdstate ) {
            if ( c_stop != conn->rdstate )
                conn->rdstate = c_stop;
            conn_read(conn);
        }
    }

BREAK_LABEL:

    return;
}
