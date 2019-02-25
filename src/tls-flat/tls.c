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
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/ssl_ticket.h"
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"
#include "mbedtls/util.h"
#include "internal.h"


extern const unsigned char root_crt[];
extern const size_t root_crt_len;
extern const unsigned char root_key[];
extern const size_t root_key_len;

/*
 * 供 SERVER 端使用的 TLS 环境
 */
typedef struct _TLS_SRV{
    mbedtls_x509_crt root_crt;                      // 创建签名用的根证书
    mbedtls_pk_context root_key;                    // 创建签名用的根证书私钥

    mbedtls_pk_context mykey;                       // 所有自签子证书共用同一个KEY

    mbedtls_ssl_config conf;                        // SSL设置
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_cache_context cache;
    mbedtls_ssl_ticket_context ticket_ctx;
} TLS_SRV;

/*
 * 供 CLIENT 端使用的 TLS 环境
 */
typedef struct _TLS_CLT{
    mbedtls_ssl_config conf;                        // SSL设置
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
} TLS_CLT;

/*
 * MBEDTLS 环境
 */
typedef struct _TLS{
    TLS_SRV srv;
    TLS_CLT clt;
} TLS;


static void tls_debug_out(
    void *ctx, int level,
    const char *file, int line,
    const char *str);

static int tls_handshake_sni_cb(
    void *p_info,
    mbedtls_ssl_context *ssl,
    const unsigned char *name,
    size_t name_len);

static int tls_clt_init(TLS_CLT *clt);
static int tls_srv_init(TLS_SRV *srv);
static void do_handshake(TLS_SESSION *ts);
static void do_transmit(TLS_SESSION *ts);

static TLS Tls;

int tls_init(void) {
    int ret;

    memset(&Tls, 0, sizeof(Tls));
    ret = tls_srv_init(&Tls.srv);
    if ( 0 == ret )
        ret = tls_clt_init(&Tls.clt);

    return ret;
}


/*
 * 初始化 tls server 端
 */
static int tls_srv_init(TLS_SRV *srv) {
    int ret;

    mbedtls_x509_crt_init(&srv->root_crt);
    mbedtls_pk_init(&srv->root_key);

    mbedtls_ssl_config_init(&srv->conf);
    mbedtls_entropy_init(&srv->entropy);
    mbedtls_ctr_drbg_init(&srv->ctr_drbg);
    mbedtls_ssl_cache_init(&srv->cache);
    mbedtls_ssl_ticket_init(&srv->ticket_ctx);

    mbedtls_ssl_conf_dbg(&srv->conf, tls_debug_out, stdout);

    mbedtls_debug_set_threshold(0);

    ret = mbedtls_ctr_drbg_seed(
        &srv->ctr_drbg,
        mbedtls_entropy_func,
        &srv->entropy,
        NULL,
        0
    );
    BREAK_ON_FAILURE(ret);

    ret = mbedtls_x509_crt_parse(
        &srv->root_crt,
        root_crt,
        root_crt_len);
    BREAK_ON_FAILURE(ret);

    ret = mbedtls_pk_parse_key(
        &srv->root_key,
        root_key,
        root_key_len,
        NULL,
        0);
    BREAK_ON_FAILURE(ret);

    ret = mbedtls_ssl_config_defaults(
        &srv->conf,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    BREAK_ON_FAILURE(ret);

    mbedtls_ssl_conf_authmode(&srv->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&srv->conf, mbedtls_ctr_drbg_random, &srv->ctr_drbg);

    mbedtls_ssl_conf_session_cache(
        &srv->conf,
        &srv->cache,
        mbedtls_ssl_cache_get,
        mbedtls_ssl_cache_set
    );

    ret = mbedtls_ssl_ticket_setup(
        &srv->ticket_ctx,
        mbedtls_ctr_drbg_random,
        &srv->ctr_drbg,
        MBEDTLS_CIPHER_AES_256_GCM,
        86400                           // recommended value ONE DAY
    );
    BREAK_ON_FAILURE(ret);

#ifdef MBEDTLS_SSL_SESSION_TICKETS
    mbedtls_ssl_conf_session_tickets_cb(
        &srv->conf,
        mbedtls_ssl_ticket_write,
        mbedtls_ssl_ticket_parse,
        &srv->ticket_ctx
    );
#endif

    mbedtls_ssl_conf_min_version(
        &srv->conf,
        MBEDTLS_SSL_MAJOR_VERSION_3,
        MBEDTLS_SSL_MINOR_VERSION_1
    );

    mbedtls_ssl_conf_max_version(
        &srv->conf,
        MBEDTLS_SSL_MAJOR_VERSION_3,
        MBEDTLS_SSL_MINOR_VERSION_3
    );


    mbedtls_ssl_conf_sni(&srv->conf, tls_handshake_sni_cb, NULL);

    /* 不进行服务端证书设置
     * 而是在 SNI CALLBACK 时 根据SSL CONTEXT来设置不同证书 => mbedtls_ssl_set_hs_own_cert */


    mbedtls_pk_init(&srv->mykey);
    ret = mbedtls_gen_rsa_key(&srv->mykey);
    BREAK_ON_FAILURE(ret);

BREAK_LABEL:

    return ret;
}


/*
 * 初始化 tls client 端
 */
static int tls_clt_init(TLS_CLT *clt) {
    int ret;

    mbedtls_ssl_config_init(&clt->conf);
    mbedtls_entropy_init(&clt->entropy);
    mbedtls_ctr_drbg_init(&clt->ctr_drbg);

    mbedtls_ssl_conf_dbg(&clt->conf, tls_debug_out, stdout);

    ret = mbedtls_ctr_drbg_seed(
        &clt->ctr_drbg,
        mbedtls_entropy_func,
        &clt->entropy,
        NULL,
        0
    );
    BREAK_ON_FAILURE(ret);

    ret = mbedtls_ssl_config_defaults(
        &clt->conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    BREAK_ON_FAILURE(ret);

    mbedtls_ssl_conf_authmode(&clt->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    mbedtls_ssl_conf_rng(
        &clt->conf,
        mbedtls_ctr_drbg_random,
        &clt->ctr_drbg
    );

    mbedtls_ssl_conf_min_version(
        &clt->conf,
        MBEDTLS_SSL_MAJOR_VERSION_3,
        MBEDTLS_SSL_MINOR_VERSION_1
    );

    mbedtls_ssl_conf_max_version(
        &clt->conf,
        MBEDTLS_SSL_MAJOR_VERSION_3,
        MBEDTLS_SSL_MINOR_VERSION_3
    );

BREAK_LABEL:

    return ret;
}

void tls_clear(void) {
    /* srv */
    mbedtls_x509_crt_free(&Tls.srv.root_crt);
    mbedtls_pk_free(&Tls.srv.root_key);
    mbedtls_ssl_config_free(&Tls.srv.conf);
    mbedtls_entropy_free(&Tls.srv.entropy);
    mbedtls_ctr_drbg_free(&Tls.srv.ctr_drbg);
    mbedtls_ssl_cache_free(&Tls.srv.cache);
    mbedtls_ssl_ticket_free(&Tls.srv.ticket_ctx);
    mbedtls_pk_free(&Tls.srv.mykey);

    /* clt */
    mbedtls_ssl_config_free(&Tls.clt.conf);
    mbedtls_entropy_free(&Tls.clt.entropy);
    mbedtls_ctr_drbg_free(&Tls.clt.ctr_drbg);
}

static void tls_debug_out(
    void *ctx, int level,
    const char *file, int line,
    const char *str) {
    ((void)level);

    mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *)ctx);
}

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
static int tls_handshake_sni_cb(
    void *p_info,
    mbedtls_ssl_context *ssl,
    const unsigned char *name,
    size_t name_len) {
    TLS_SESSION *ts;
    STREAM_SESSION_TLF *ss;
    int result = -1;

    (void)p_info;

    ts = CONTAINER_OF(ssl, TLS_SESSION, ssl);
    ss = ts->ss;

    BREAK_ON_FALSE(name_len < sizeof(ss->sni_name));
    memcpy(ss->sni_name, name, name_len);

    tlsflat_notify(4, "%4d [%s] SNI", ss->index, ss->sni_name);

    result = 0;

BREAK_LABEL:

    return result;
}

int tls_associate_context(mbedtls_ssl_context *ssl,  int as_server) {
    int result;
    TLS *tls;

    tls = &Tls;

    mbedtls_ssl_config *conf = as_server ? &tls->srv.conf : &tls->clt.conf;

    result = mbedtls_ssl_setup(ssl, conf);

    return result;
}

int tls_recv_done_do_next(TLS_SESSION *ts) {
    int ret = PASS;

    switch ( ts->tls_state ) {
    case Tls_HandShaking:
        ret = handle_tls_handshake(ts);
        break;
    case Tls_Transmitting:
        ret = handle_tls_transmit(ts);
        break;
    default:
        UNREACHABLE();
        break;
    }

    return ret;
}

void tls_send_done_do_next(TLS_SESSION *ts) {
    switch ( ts->tls_state ) {
    case Tls_HandShaking:
        do_handshake(ts);
        break;
    case Tls_Transmitting:
        do_transmit(ts);
        break;
    default:
        UNREACHABLE();
        break;
    }
}

static void do_handshake(TLS_SESSION *ts) {
    handle_tls_handshake(ts);
}

static void do_transmit(TLS_SESSION *ts) {
    TLS_SESSION *ts_p;
    int ret;

    ts_p = ts->is_local ? &ts->ss->clt : &ts->ss->srv;
    ASSERT(Write_Waitack == ts->wrstate);

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
        &Tls.srv.mykey,
        &Tls.srv.root_crt,
        &Tls.srv.root_key,
        NULL);
    BREAK_ON_FAILURE(ret);

    ret = crt_pool_add(sni_name, crt, &Tls.srv.mykey);
    if ( 0 == ret ) {
        *ret_crt = crt;
        *ret_pk = &Tls.srv.mykey;
    }

BREAK_LABEL:

    if ( 0 != ret && crt ) {
        mbedtls_x509_crt_free(crt);
        free(crt);
    }

    return ret;
}
