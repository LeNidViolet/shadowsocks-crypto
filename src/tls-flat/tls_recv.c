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

// ReSharper disable once CppParameterMayBeConst
int on_tls_recv(void *ctx, unsigned char *buf, size_t len) {
    tls_session *ts;
    stream_session *ss;
    const size_t wants = len;
    size_t eaten = 0;

    ts = (tls_session *)ctx;

    if ( ts->buf_in.data_len ) {
        eaten = wants > ts->buf_in.data_len ? ts->buf_in.data_len : wants;
        memcpy(buf, ts->buf_in.data_base, eaten);

        ts->buf_in.data_len -= eaten;
        if ( ts->buf_in.data_len ) {
            /* 还有剩余数据待取 */
            ts->buf_in.data_base += eaten;
        } else {
            /* 数据已空 */
            ts->buf_in.data_base = ts->buf_in.buf_base;
        }
    }

    ss = ts->ss;
    tlsflat_on_msg(LOG_DEBUG, "%4d [%s] <== %s SIDE WANT %d EATEN %d",
                   ss->index,
                   ss->sni_name[0] ? ss->sni_name : ss->remote.domain,
                   ts->is_local ? "SERVER" : "CLIENT",
                   (int)len,
                   eaten);

    return (int)eaten > 0 ? (int)eaten : MBEDTLS_ERR_SSL_WANT_READ;
}
