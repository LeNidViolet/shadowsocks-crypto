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

#ifndef TLS_FLAT_INTERBAL_H
#define TLS_FLAT_INTERBAL_H


#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/ssl_ticket.h"
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

    BUF_RANGE buf_in;
    BUF_RANGE buf_out;
    int is_local;
    int wrstate;
    int wait_ack_len;
} tls_session;

typedef struct stream_session_{
    unsigned int index;
    ADDRESS local;
    ADDRESS remote;

    char sni_name[128];

    tls_session srv;
    tls_session clt;

    void *stream_id;
    void *caller_ctx;

    unsigned int bytes_out;
    unsigned int bytes_in;
} stream_session;

/*
 * 供 SERVER 端使用的 TLS 环境
 */
typedef struct {
    mbedtls_x509_crt root_crt;                      // 创建签名用的根证书
    mbedtls_pk_context root_key;                    // 创建签名用的根证书私钥

    mbedtls_pk_context mykey;                       // 所有自签子证书共用同一个KEY

    mbedtls_ssl_config conf;                        // SSL设置
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_cache_context cache;
    mbedtls_ssl_ticket_context ticket_ctx;
} tls_srv;

/*
 * 供 CLIENT 端使用的 TLS 环境
 */
typedef struct {
    mbedtls_ssl_config conf;                        // SSL设置
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
} tls_clt;

/*
 * MBEDTLS 环境
 */
typedef struct {
    tls_srv srv;
    tls_clt clt;
} TLS;

/* HANDLER.C */
void tlsflat_on_msg(int level, const char *format, ...);
void tlsflat_plain_stream(stream_session *ss, int direct, const char *data, size_t data_len);

/* TLS.C */
int  tls_associate_context(mbedtls_ssl_context *ssl,  int as_server);
int  tls_recv_done_do_next(tls_session *ts);
int  tls_resign(
    const char *sni_name,
    const mbedtls_x509_crt *ws_crt,
    mbedtls_x509_crt **ret_crt,
    mbedtls_pk_context **ret_pk);

/* TLS_HANDSHAKE.C */
int  handle_tls_handshake(tls_session *ts);
/* TLS_TRANSMIT.C */
int  handle_tls_transmit(tls_session *ts);

/* UTIL.C */
void buf_range_alloc(BUF_RANGE *mr, size_t size);
void buf_range_relloc(BUF_RANGE *mr, size_t size);
void buf_range_free(BUF_RANGE *mr);

/* CRT_POOL.C */
int  crt_pool_init(void);
int  crt_pool_add(
    const char *domain,
    mbedtls_x509_crt *crt,
    mbedtls_pk_context *pk);
int  crt_pool_get(
    const char *domain,
    mbedtls_x509_crt **crt,
    mbedtls_pk_context **pk);
void crt_pool_clear(void);


/* EXTERNAL FUNCTION */
void sscrypto_on_msg(int level, const char *msg);
void sscrypto_tls_on_plain_stream(const char *data, size_t data_len, int direct, void *ss_ctx);


extern TLS tls;
#endif //TLS_FLAT_INTERBAL_H
