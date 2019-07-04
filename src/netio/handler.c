/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/22.
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

typedef struct {
    write_stream_out_callback callback;
    void *param;
} snd_ctx;

static void ssnetio_write_stream_out_done(uv_write_t *req, int status);

void ssnetio_on_msg(int level, const char *format, ...) {
    va_list ap;
    char msg[1024];

    va_start(ap, format);
    vsnprintf(msg, sizeof(msg), format, ap);
    va_end(ap);

    sscrypto_on_msg(level, msg);
}

void ssnetio_on_bind(const char *host, unsigned short port) {
    sscrypto_on_bind(host, port);
}

void ssnetio_on_connection_made(proxy_node *pn) {
    address_pair pair;

    pair.local = &pn->incoming.peer;
    pair.remote = &pn->outgoing.peer;

    sscrypto_on_stream_connection_made(&pair, pn->ctx);
}

void ssnetio_on_new_stream(connection *conn) {
    void *ctx = NULL;

    sscrypto_on_new_stream(&conn->peer, &ctx, conn->pn);
    conn->pn->ctx = ctx;
}

void ssnetio_on_stream_teardown(proxy_node *pn) {
    sscrypto_on_stream_teardown(pn->ctx);
}

void ssnetio_on_new_dgram(address *local, address *remote, void **ctx) {
    address_pair pair;

    pair.local = local;
    pair.remote = remote;

    sscrypto_on_new_dgram(&pair, ctx);
}

void ssnetio_on_dgram_teardown(void *ctx) {
    sscrypto_on_dgram_teardown(ctx);
}

int ssnetio_on_stream_encrypt(connection *conn, int offset) {
    int ret;
    buf_range mr;

    mr.buf_base = conn->ss_buf.buf_base;
    mr.buf_len = conn->ss_buf.buf_len;
    mr.data_base = mr.buf_base + offset;
    mr.data_len = (size_t)conn->result - offset;

    conn->ss_buf.data_base = conn->ss_buf.buf_base + offset;
    conn->ss_buf.data_len = (size_t)conn->result - offset;
    ret = sscrypto_on_stream_encrypt(&mr, conn->pn->ctx);

    conn->ss_buf.data_base = mr.data_base;
    conn->ss_buf.data_len = mr.data_len;

    return ret;
}

int ssnetio_on_stream_decrypt(connection *conn, int offset) {
    int ret;
    buf_range mr;

    mr.buf_base = conn->ss_buf.buf_base;
    mr.buf_len = conn->ss_buf.buf_len;
    mr.data_base = mr.buf_base + offset;
    mr.data_len = (size_t)conn->result - offset;

    conn->ss_buf.data_base = conn->ss_buf.buf_base + offset;
    conn->ss_buf.data_len = (size_t)conn->result - offset;
    ret = sscrypto_on_stream_decrypt(&mr, conn->pn->ctx);

    conn->ss_buf.data_base = mr.data_base;
    conn->ss_buf.data_len = mr.data_len;

    return ret;
}

int ssnetio_on_dgram_encrypt(buf_range *buf, int offset) {
    int ret;
    buf_range mr;

    mr.buf_base = buf->buf_base;
    mr.buf_len = buf->buf_len;
    mr.data_base = mr.buf_base + offset;
    mr.data_len = buf->data_len - offset;

    ret = sscrypto_on_dgram_encrypt(&mr);

    buf->data_base = mr.data_base;
    buf->data_len = mr.data_len;

    return ret;
}

int ssnetio_on_dgram_decrypt(buf_range *buf, int offset) {
    int ret;
    buf_range mr;

    mr.buf_base = buf->buf_base;
    mr.buf_len = buf->buf_len;
    mr.data_base = mr.buf_base + offset;
    mr.data_len = buf->data_len - offset;

    ret = sscrypto_on_dgram_decrypt(&mr);

    buf->data_base = mr.data_base;
    buf->data_len = mr.data_len;

    return ret;
}

int ssnetio_on_plain_stream(connection *conn) {
    int action;
    int direct = conn == &conn->pn->incoming ? STREAM_UP : STREAM_DOWN;
    buf_range mr;

    mr.buf_base = conn->ss_buf.buf_base;
    mr.buf_len = conn->ss_buf.buf_len;
    mr.data_base = conn->ss_buf.data_base;
    mr.data_len = conn->ss_buf.data_len;

    action = sscrypto_on_plain_stream(
        &mr,
        direct,
        conn->pn->ctx);

    return action;
}

void ssnetio_on_plain_dgram(buf_range *buf, int direct, void *ctx) {
    buf_range mr;

    mr.buf_base = buf->buf_base;
    mr.buf_len = buf->buf_len;
    mr.data_base = buf->data_base;
    mr.data_len = buf->data_len;

    sscrypto_on_plain_dgram(
        &mr,
        direct,
        ctx);
}

/* SERVER SIDE ONLY */
int ssnetio_write_stream_out(
    buf_range *buf, int direct, void *stream_id,
    write_stream_out_callback callback, void *param) {
    int ret = -1;
    proxy_node *pn;
    connection *conn;
    uv_buf_t buf_t;
    snd_ctx *snd_ctx;

    BREAK_ON_NULL(buf);
    BREAK_ON_FALSE(STREAM_UP == direct || STREAM_DOWN == direct);
    BREAK_ON_NULL(stream_id);

    pn = (proxy_node*)stream_id;
    conn = STREAM_UP == direct ? &pn->outgoing : &pn->incoming;

    if ( STREAM_DOWN == direct ) {
        ret = sscrypto_on_stream_encrypt(buf, conn->pn->ctx);
        ASSERT(0 == ret);
        ret = -2;
    }

    ASSERT(c_stop == conn->wrstate || c_done == conn->wrstate);
    conn->wrstate = c_busy;

    buf_t = uv_buf_init(buf->data_base, (unsigned int)buf->data_len);

    ENSURE((snd_ctx = malloc(sizeof(*snd_ctx))) != NULL);
    snd_ctx->callback = callback;
    snd_ctx->param = param;
    uv_req_set_data((uv_req_t*)&conn->write_req, snd_ctx);
    if ( 0 != uv_write(&conn->write_req,
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
    connection *conn;
    snd_ctx *snd_ctx;
    int direct;

    conn = CONTAINER_OF(req, connection, write_req);
    conn->pn->outstanding--;
    ASSERT(c_busy == conn->wrstate);
    conn->wrstate = c_stop;

    direct = conn == &conn->pn->incoming ? STREAM_DOWN : STREAM_UP;

    snd_ctx = uv_req_get_data((uv_req_t*)req);
    if ( snd_ctx->callback )
        snd_ctx->callback(snd_ctx->param, direct, status, conn->pn->ctx);

    free(snd_ctx);
}

void ssnetio_stream_pause(void *stream_id, int direct, int pause) {
    proxy_node *pn;
    connection *conn;

    BREAK_ON_NULL(stream_id);
    BREAK_ON_FALSE(STREAM_UP == direct || STREAM_DOWN == direct);

    pn = (proxy_node*)stream_id;
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
