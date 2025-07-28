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
#include "mbedtls/net.h"
#include "internal.h"

extern ioctl_port ioctlp;

int handle_tls_transmit(tls_session *ts) {
    stream_session *ss;
    tls_session *ts_p;
    int ret, action;
    size_t extra_len, new_len;

    ASSERT(tls_transmitting == ts->tls_state);
    ss = ts->ss;

    ts_p = ts->is_local ? &ss->clt : &ss->srv;
    ASSERT(write_idel == ts_p->wrstate);
    ts_p->buf_out.data_base = ts_p->buf_out.buf_base;

    ret = mbedtls_ssl_read(
        &ts->ssl,
        (unsigned char*)ts_p->buf_out.buf_base,
        ts_p->buf_out.buf_len);

    if( MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY == ret || 0 == ret ) {
        tlsflat_on_msg(LOG_DEBUG, "%4d [%s] MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY (%d) ON %s SIDE",
                       ss->index,
                       ss->sni_name,
                       ret,
                       ts->is_local ? "SERVER" : "CLIENT");
        mbedtls_ssl_close_notify(&ts_p->ssl);
        action = TERMINATE;
        BREAK_NOW;
    }

    if ( MBEDTLS_ERR_NET_CONN_RESET == ret ) {
        tlsflat_on_msg(LOG_WARN, "%4d [%s] MBEDTLS_ERR_NET_CONN_RESET ON %s SIDE",
                       ss->index,
                       ss->sni_name,
                       ts->is_local ? "SERVER" : "CLIENT");
        action = TERMINATE;
        BREAK_NOW;
    }

    if ( MBEDTLS_ERR_SSL_CLIENT_RECONNECT == ret ) {
        tlsflat_on_msg(LOG_WARN, "%4d [%s] MBEDTLS_ERR_SSL_CLIENT_RECONNECT ON %s SIDE",
                       ss->index,
                       ss->sni_name,
                       ts->is_local ? "SERVER" : "CLIENT");
        /* TODO: HANDLE MBEDTLS_ERR_SSL_CLIENT_RECONNECT CORRECT */
        action = TERMINATE;
        BREAK_NOW;
    }

    if ( MBEDTLS_ERR_SSL_WANT_READ == ret ) {
        tlsflat_on_msg(LOG_DEBUG, "%4d [%s] mbedtls_ssl_read MBEDTLS_ERR_SSL_WANT_READ %s SIDE",
                       ss->index,
                       ss->sni_name,
                       ts->is_local ? "SERVER" : "CLIENT");

        ioctlp.stream_pause(ss->stream_id, ts->is_local ? STREAM_DOWN : STREAM_UP, 0);
        action = NEEDMORE;
        BREAK_NOW;
    }

    /* Should not happen */
    ASSERT(MBEDTLS_ERR_SSL_WANT_WRITE != ret);

    if ( ret < 0 ) {
        tlsflat_on_msg(LOG_WARN, "%4d [%s] mbedtls_ssl_read FAILED[%d] ON %s SIDE",
                       ss->index,
                       ss->sni_name,
                       ret,
                       ts->is_local ? "SERVER" : "CLIENT");
        action = TERMINATE;
        BREAK_NOW;
    }
    ts_p->buf_out.data_len = (size_t)ret;

    extra_len = mbedtls_ssl_get_bytes_avail(&ts->ssl);
    if( 0 != extra_len ) {
        new_len = extra_len + ret;
        buf_range_relloc(&ts_p->buf_out, new_len);

        ret = mbedtls_ssl_read(
            &ts->ssl,
            (unsigned char*)ts_p->buf_out.data_base + ts_p->buf_out.data_len,
            extra_len);
        ASSERT(ret == extra_len);

        ts_p->buf_out.data_len += ret;
    }

    tlsflat_plain_stream(
        ss,
        ts_p->is_local ? STREAM_DOWN : STREAM_UP,
        ts_p->buf_out.data_base,
        ts_p->buf_out.data_len);

    mbedtls_ssl_write(
        &ts_p->ssl,
        (unsigned char*)ts_p->buf_out.data_base,
        ts_p->buf_out.data_len);

    action = handle_tls_transmit(ts);
BREAK_LABEL:

    return action;
}
