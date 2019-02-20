/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/23.
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
#include <stdlib.h>
#include <string.h>
#include "internal.h"

static void on_tls_send_done(void *param, int direct, int status, void *ctx);

typedef struct {
    MEM_RANGE mr;
    size_t snd_len;
    TLS_SESSION *ts;
}TLS_SND_CTX;

int on_tls_send(void *ctx, const unsigned char *buf, size_t len) {
    TLS_SESSION *ts;
    STREAM_SESSION_TLF *ss;
    int direct, ret;
    TLS_SND_CTX *tls_snd_ctx = NULL;

    ts = (TLS_SESSION *)ctx;
    ss = ts->ss;
    direct = ts->is_local ? STREAM_DOWN : STREAM_UP;

    switch ( ts->wrstate ) {
    case Write_Idel:
        break;
    case Write_Sending:
        tlsflat_notify(
            2,
            "%4d [%s] SENDING STH WHILE BUSYING AT %s SIDE",
            ss->index,
            ss->sni_name[0] ? ss->sni_name : ss->remote.host,
            ts->is_local ? "SERVER" : "CLIENT"
        );
        ret = -1;
        BREAK_NOW;
    case Write_Waitack:
        ASSERT(ts->wait_ack_len);
        ret = ts->wait_ack_len;

        ts->wait_ack_len = 0;
        ts->wrstate = Write_Idel;

        BREAK_NOW;
    default:
        UNREACHABLE();
    }

    tls_snd_ctx = malloc(sizeof(*tls_snd_ctx));
    CHECK(tls_snd_ctx);
    memset(tls_snd_ctx, 0, sizeof(*tls_snd_ctx));
    mem_range_alloc(&tls_snd_ctx->mr, len + 64);
    memcpy(tls_snd_ctx->mr.buf_base, buf, len);
    tls_snd_ctx->mr.data_len = len;
    tls_snd_ctx->snd_len = len;
    tls_snd_ctx->ts = ts;

    ret = Ioctl.write_stream_out(
        &tls_snd_ctx->mr,
        direct,
        ts->ss->stream_id,
        on_tls_send_done,
        tls_snd_ctx);
    ASSERT(0 == ret);

    ts->wrstate = Write_Sending;
    ret = MBEDTLS_ERR_SSL_WANT_WRITE;

BREAK_LABEL:

    return ret;
}

static void on_tls_send_done(void *param, int direct, int status, void *ctx) {
    STREAM_SESSION_TLF *ss;
    TLS_SESSION *ts;
    TLS_SND_CTX *tls_snd_ctx = NULL;

    (void)direct;
    (void)ctx;

    tls_snd_ctx = (TLS_SND_CTX *)param;
    CHECK(tls_snd_ctx);
    ts = tls_snd_ctx->ts;
    ss = ts->ss;

    ASSERT(Write_Sending == ts->wrstate);

    if ( 0 == status ) {
        ts->wrstate = Write_Waitack;
        ts->wait_ack_len = (int)tls_snd_ctx->snd_len;
        tls_send_done_do_next(ts);
    } else {
        tlsflat_notify(1, "%4d [%s] TLS %s SIDE SEND DATA OUT FAILED[%d]",
                       ss->index,
                       ss->sni_name[0] ? ss->sni_name : ss->remote.host,
                       ts->is_local ? "SERVER" : "CLIENT",
                       status);
        ss->closing = 1;
    }

    mem_range_free(&tls_snd_ctx->mr);
    free(tls_snd_ctx);
}
