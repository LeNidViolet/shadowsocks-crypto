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

#ifndef TLS_FLAT_INTERBAL_H
#define TLS_FLAT_INTERBAL_H

#include <assert.h>
#include "mbedtls/ssl.h"
#include "../comm/comm.h"

enum {
    tls_handshaking,
    tls_transmitting
};

enum {
    write_idel,
    write_sending,
    write_waitack
};

typedef struct {
    struct stream_session_ *ss;
    mbedtls_ssl_context ssl;
    int tls_state;

    buf_range buf_in;
    buf_range buf_out;
    int is_local;
    int wrstate;
    int wait_ack_len;
} tls_session;

typedef struct stream_session_{
    unsigned int index;
    address local;
    address remote;

    char sni_name[128];

    int closing;

    tls_session srv;
    tls_session clt;

    void *stream_id;
    void *caller_ctx;

    unsigned int bytes_out;
    unsigned int bytes_in;
} stream_session;

/* HANDLER.C */
void tlsflat_on_msg(int level, const char *format, ...);
void tlsflat_plain_stream(stream_session *ss, int direct, const char *data, size_t data_len);

/* TLS.C */
int tls_init(void);
void tls_clear(void);
int tls_associate_context(mbedtls_ssl_context *ssl,  int as_server);
int tls_recv_done_do_next(tls_session *ts);
void tls_send_done_do_next(tls_session *ts);
int tls_resign(
    const char *sni_name,
    const mbedtls_x509_crt *ws_crt,
    mbedtls_x509_crt **ret_crt,
    mbedtls_pk_context **ret_pk);

/* TLS_SEND.C */
int on_tls_send(void *ctx, const unsigned char *buf, size_t len);
/* TLS_RECV.C */
int on_tls_recv(void *ctx, unsigned char *buf, size_t len);

/* TLS_HANDSHAKE.C */
int handle_tls_handshake(tls_session *ts);
/* TLS_TRANSMIT.C */
int handle_tls_transmit(tls_session *ts);

/* UTIL.C */
void buf_range_alloc(buf_range *mr, size_t size);
void buf_range_relloc(buf_range *mr, size_t size);
void buf_range_free(buf_range *mr);

/* CRT_POOL.C */
int crt_pool_init(void);
int crt_pool_add(
    const char *domain,
    mbedtls_x509_crt *crt,
    mbedtls_pk_context *pk);
int crt_pool_get(
    const char *domain,
    mbedtls_x509_crt **crt,
    mbedtls_pk_context **pk);
void crt_pool_clear(void);


/* EXTERNAL FUNCTION */
void sscrypto_on_msg(int level, const char *msg);
void sscrypto_tls_on_plain_stream(const char *data, size_t data_len, int direct, void *ss_ctx);
#endif //TLS_FLAT_INTERBAL_H
