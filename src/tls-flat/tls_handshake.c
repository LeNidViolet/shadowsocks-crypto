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
#include "internal.h"

extern ioctl_port ioctlp;

int handle_tls_handshake(tls_session *ts) {
    int ret, action;
    stream_session *ss;
    const mbedtls_x509_crt *ws_crt;
    mbedtls_x509_crt *crt;
    mbedtls_pk_context *pk;

    ASSERT(tls_handshaking == ts->tls_state);
    ss = ts->ss;

    ret = mbedtls_ssl_handshake(&ts->ssl);
    switch ( ret ) {
    case 0:
        ts->tls_state = tls_transmitting;

        if ( ts->is_local ) {
            tlsflat_on_msg(
                LOG_KEY,
                "%4d [%s] SSL HANDSHAKE DONE",
                ss->index,
                ss->sni_name[0] ? ss->sni_name : ss->remote.domain);

            /* Local(server) ssl handshake done. */
            /* 检查有没有要发往webserver的数据 */
            ioctlp.stream_pause(ss->stream_id, STREAM_UP, 0);
            handle_tls_transmit(ts);

            action = REJECT;
        } else {
            /* Remote(client) ssl handshake done. */
            /* 重签证书 */
            ws_crt = mbedtls_ssl_get_peer_cert(&ts->ssl);
            ASSERT(ws_crt);
            ret = tls_resign(ss->sni_name, ws_crt, &crt, &pk);
            if ( 0 != ret ) {
                tlsflat_on_msg(
                    LOG_ERROR,
                    "%4d [%s] RESIGN CERT FAILED [%X]",
                    ss->index,
                    ss->sni_name,
                    ret);
                action = TERMINATE;
            } else {
                /* 继续server侧的握手 */
                mbedtls_ssl_set_hs_own_cert(&ss->srv.ssl, crt, pk);
                handle_tls_handshake(&ss->srv);

                action = REJECT;
            }
        }

        break;

    case MBEDTLS_ERR_SSL_WANT_READ:
        if ( MBEDTLS_SSL_SNI_HOLDING == ts->ssl.state ) {
            ASSERT(ts->is_local);

            /* 当得到SNI之后我们在这里进行 CLIENT 侧的SSL握手以得到证书 */
            mbedtls_ssl_set_hostname(&ss->clt.ssl, ss->sni_name);
            handle_tls_handshake(&ss->clt);

            action = REJECT;
        } else {
            /* Need more data. */
            ioctlp.stream_pause(ss->stream_id, ts->is_local ? STREAM_DOWN : STREAM_UP, 0);
            action = NEEDMORE;
        }
        break;

    case MBEDTLS_ERR_SSL_WANT_WRITE:
        /* Nothing to do */
        action = REJECT;
        break;

    case MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO:
        ASSERT(ts->is_local);

        /* TODO: Not TLS Data Stream, as a Tcp Data Stream to proxy */

        tlsflat_on_msg(
            LOG_WARN,
            "%4d [%s] MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO %s SIDE",
            ss->index,
            ss->sni_name[0] ? ss->sni_name : ss->remote.domain,
            ts->is_local ? "SERVER" : "CLIENT"
        );
        action = TERMINATE;
        break;

    default:
        tlsflat_on_msg(
            LOG_WARN,
            "%4d [%s] HANDSHAKE mbedtls_ssl_handshake FAILED[%d] AT %s SIDE",
            ss->index,
            ss->sni_name[0] ? ss->sni_name : ss->remote.domain,
            ret,
            ts->is_local ? "SERVER" : "CLIENT"
        );
        action = TERMINATE;
        break;
    }

    return action;
}
