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
#include <stdlib.h>
#include <string.h>
#include "internal.h"

extern ioctl_port ioctlp;

typedef struct {
    BUF_RANGE buf;
    size_t snd_len;
    tls_session *ts;
} tls_snd_ctx;

int on_tls_send(void *ctx, const unsigned char *buf, size_t len) {
    tls_session *ts;
    int direct, ret;
    tls_snd_ctx *snd_ctx = NULL;

    ts = (tls_session *)ctx;
    direct = ts->is_local ? STREAM_DOWN : STREAM_UP;

    snd_ctx = malloc(sizeof(*snd_ctx));
    CHECK(snd_ctx);
    memset(snd_ctx, 0, sizeof(*snd_ctx));
    buf_range_alloc(&snd_ctx->buf, len + 64);
    memcpy(snd_ctx->buf.buf_base, buf, len);
    snd_ctx->buf.data_len = len;
    snd_ctx->snd_len = len;
    snd_ctx->ts = ts;

    ret = ioctlp.write_stream_out(
        (char*)buf,
        len,
        direct,
        ts->ss->stream_id);
    ASSERT(0 == ret);

    /* 这里返回 MBEDTLS_ERR_SSL_WANT_WRITE 之后mbedtls会处于'等待'状态 */
    /* 接下来的流程需要on_tls_send_done再调用至此, 并携带状态 write_waitack 来触发 */
//    ts->wrstate = write_sending;
//    ret = MBEDTLS_ERR_SSL_WANT_WRITE;
    ret = (int)len;

BREAK_LABEL:

    return ret;
}
