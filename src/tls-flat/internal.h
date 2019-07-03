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
    Tls_HandShaking,
    Tls_Transmitting
};

enum {
    Write_Idel,
    Write_Sending,
    Write_Waitack
};

typedef struct TLS_SESSION_{
    struct STREAM_SESSION_ *ss;
    mbedtls_ssl_context ssl;
    int tls_state;

    buf_range buf_in;
    buf_range buf_out;
    int is_local;
    int wrstate;
    int wait_ack_len;
} TLS_SESSION;

typedef struct STREAM_SESSION_{
    unsigned int index;
    address local;
    address remote;

    char sni_name[128];

    int closing;

    TLS_SESSION srv;
    TLS_SESSION clt;

    void *stream_id;
    void *caller_ctx;

    unsigned int bytes_out;
    unsigned int bytes_in;
} STREAM_SESSION;

/* HANDLER.C */
void tlsflat_notify(int level, const char *format, ...);
void tlsflat_plain_stream(STREAM_SESSION *ss, int direct, const char *data, size_t data_len);

/* TLS.C */
int tls_init(void);
void tls_clear(void);
int tls_associate_context(mbedtls_ssl_context *ssl,  int as_server);
int tls_recv_done_do_next(TLS_SESSION *ts);
void tls_send_done_do_next(TLS_SESSION *ts);
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
int handle_tls_handshake(TLS_SESSION *ts);
/* TLS_TRANSMIT.C */
int handle_tls_transmit(TLS_SESSION *ts);

/* UTIL.C */
void mem_range_alloc(buf_range *mr, size_t size);
void mem_range_relloc(buf_range *mr, size_t size);
void mem_range_free(buf_range *mr);

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
