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
#include <string.h>
#include "mbedtls/util.h"
#include "internal.h"


static void do_handshake_next(tls_session *ts);
static void do_transmit_next(tls_session *ts);

/**
 * \brief                           SNI callback.
 *                                  该回调发生于 SSL 握手 CLIENT HELLO阶段
 *
 * \param p_info                    context
 * \param ssl                       当前握手ssl context
 * \param name                      域名
 * \param name_len                  域名长度
 *
 * \return                          0 if success
 */
int tls_handshake_sni_cb(
    void *p_info,
    mbedtls_ssl_context *ssl,
    const unsigned char *name,
    size_t name_len) {
    tls_session *ts;
    stream_session *ss;
    int result = -1;

    (void)p_info;

    ts = CONTAINER_OF(ssl, tls_session, ssl);
    ss = ts->ss;

    BREAK_ON_FALSE(name_len < sizeof(ss->sni_name));
    memcpy(ss->sni_name, name, name_len);

    tlsflat_on_msg(INFO, "%4d [%s] SNI", ss->index, ss->sni_name);

    result = 0;

BREAK_LABEL:

    return result;
}

int tls_associate_context(mbedtls_ssl_context *ssl,  int as_server) {
    int result;

    mbedtls_ssl_config *conf = as_server ? &tls.srv.conf : &tls.clt.conf;

    result = mbedtls_ssl_setup(ssl, conf);

    return result;
}

int tls_recv_done_do_next(tls_session *ts) {
    int ret = PASS;

    switch ( ts->tls_state ) {
    case tls_handshaking:
        ret = handle_tls_handshake(ts);
        break;
    case tls_transmitting:
        ret = handle_tls_transmit(ts);
        break;
    default:
        UNREACHABLE();
        break;
    }

    return ret;
}

void tls_send_done_do_next(tls_session *ts) {
    switch ( ts->tls_state ) {
    case tls_handshaking:
        do_handshake_next(ts);
        break;
    case tls_transmitting:
        do_transmit_next(ts);
        break;
    default:
        UNREACHABLE();
        break;
    }
}

static void do_handshake_next(tls_session *ts) {
    handle_tls_handshake(ts);
}

static void do_transmit_next(tls_session *ts) {
    tls_session *ts_p;
    int ret;

    ts_p = ts->is_local ? &ts->ss->clt : &ts->ss->srv;
    ASSERT(write_waitack == ts->wrstate);

    ret = mbedtls_ssl_write(
        &ts->ssl,
        (unsigned char*)ts->buf_out.data_base,
        ts->buf_out.data_len);
    if ( MBEDTLS_ERR_SSL_WANT_WRITE == ret ) {

    } else {
        ASSERT(ret == ts->buf_out.data_len);
        ts->buf_out.data_len = 0;

        handle_tls_transmit(ts_p);
    }
}


int tls_resign(
    const char *sni_name,
    const mbedtls_x509_crt *ws_crt,
    mbedtls_x509_crt **ret_crt,
    mbedtls_pk_context **ret_pk) {

    int ret;
    mbedtls_x509_crt *crt = NULL;

    ret = crt_pool_get(sni_name, ret_crt, ret_pk);
    if ( 0 == ret )
        BREAK_NOW;

    crt = malloc(sizeof(*crt));
    CHECK(crt);
    mbedtls_x509_crt_init(crt);

    ret = mbedtls_x509_crt_resign(
        crt,
        ws_crt,
        &tls.srv.mykey,
        &tls.srv.root_crt,
        &tls.srv.root_key,
        NULL);
    BREAK_ON_FAILURE(ret);

    ret = crt_pool_add(sni_name, crt, &tls.srv.mykey);
    if ( 0 == ret ) {
        *ret_crt = crt;
        *ret_pk = &tls.srv.mykey;
    }

BREAK_LABEL:

    if ( 0 != ret && crt ) {
        mbedtls_x509_crt_free(crt);
        free(crt);
    }

    return ret;
}
