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
extern ioctl_port ioctlp;

typedef struct {
    buf_range buf;
    size_t snd_len;
    tls_session *ts;
} tls_snd_ctx;

int on_tls_send(void *ctx, const unsigned char *buf, size_t len) {
    tls_session *ts;
    stream_session *ss;
    int direct, ret;
    tls_snd_ctx *snd_ctx = NULL;

    ts = (tls_session *)ctx;
    ss = ts->ss;
    direct = ts->is_local ? STREAM_DOWN : STREAM_UP;

    switch ( ts->wrstate ) {
    case write_idel:
        break;
    case write_sending:
        tlsflat_on_msg(
            WARN,
            "%4d [%s] SENDING STH WHILE BUSYING AT %s SIDE",
            ss->index,
            ss->sni_name[0] ? ss->sni_name : ss->remote.domain,
            ts->is_local ? "SERVER" : "CLIENT"
        );
        ret = -1;
        BREAK_NOW;
    case write_waitack:
        /* 确认'上次'发送数据结果 */
        ASSERT(ts->wait_ack_len);
        ret = ts->wait_ack_len;

        ts->wait_ack_len = 0;
        ts->wrstate = write_idel;

        BREAK_NOW;
    default:
        UNREACHABLE();
    }

    snd_ctx = malloc(sizeof(*snd_ctx));
    CHECK(snd_ctx);
    memset(snd_ctx, 0, sizeof(*snd_ctx));
    buf_range_alloc(&snd_ctx->buf, len + 64);
    memcpy(snd_ctx->buf.buf_base, buf, len);
    snd_ctx->buf.data_len = len;
    snd_ctx->snd_len = len;
    snd_ctx->ts = ts;

    ret = ioctlp.write_stream_out(
        &snd_ctx->buf,
        direct,
        ts->ss->stream_id,
        on_tls_send_done,
        snd_ctx);
    ASSERT(0 == ret);

    /* 这里返回 MBEDTLS_ERR_SSL_WANT_WRITE 之后mbedtls会处于'等待'状态 */
    /* 接下来的流程需要on_tls_send_done再调用至此, 并携带状态 write_waitack 来触发 */
    ts->wrstate = write_sending;
    ret = MBEDTLS_ERR_SSL_WANT_WRITE;

BREAK_LABEL:

    return ret;
}

static void on_tls_send_done(void *param, int direct, int status, void *ctx) {
    stream_session *ss;
    tls_session *ts;
    tls_snd_ctx *snd_ctx = NULL;

    (void)direct;
    (void)ctx;

    snd_ctx = (tls_snd_ctx*)param;
    CHECK(snd_ctx);
    ts = snd_ctx->ts;
    ss = ts->ss;

    ASSERT(write_sending == ts->wrstate);

    if ( 0 == status ) {
        ts->wrstate = write_waitack;
        ts->wait_ack_len = (int)snd_ctx->snd_len;

        /* 继续触发流程下一步 */
        tls_send_done_do_next(ts);
    } else {
        tlsflat_on_msg(ERROR, "%4d [%s] TLS %s SIDE SEND DATA OUT FAILED[%d]",
                       ss->index,
                       ss->sni_name[0] ? ss->sni_name : ss->remote.domain,
                       ts->is_local ? "SERVER" : "CLIENT",
                       status);
        ss->closing = 1;
    }

    buf_range_free(&snd_ctx->buf);
    free(snd_ctx);
}
