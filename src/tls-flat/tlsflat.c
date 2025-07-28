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
#include <string.h>
#include "mbedtls/debug.h"
#include "mbedtls/util.h"
#include "internal.h"


static int tls_init(const char *root_crt, const char *root_key);
static void tls_clear(void);
static void tls_debug_out(
    void *ctx, int level,
    const char *file, int line,
    const char *str);

int tls_handshake_sni_cb(
    void *p_info,
    mbedtls_ssl_context *ssl,
    const unsigned char *name,
    size_t name_len);

static int tls_clt_init(tls_clt *clt);
static int tls_srv_init(tls_srv *srv, const char *root_crt, const char *root_key);


TLS tls;
ioctl_port ioctlp = {0};


int tlsflat_init(const ioctl_port *port, const char *root_crt, const char *root_key) {
    int ret = -1;

    BREAK_ON_NULL(port);
    ioctlp = *port;

    ret = tls_init(root_crt, root_key);
    BREAK_ON_FAILURE(ret);
    ret = crt_pool_init();
    BREAK_ON_FAILURE(ret);

BREAK_LABEL:
    return ret;
}

void tlsflat_clear(void) {
    crt_pool_clear();
    tls_clear();
}



static int tls_init(const char *root_crt, const char *root_key) {
    int ret;

    memset(&tls, 0, sizeof(tls));
    ret = tls_srv_init(&tls.srv, root_crt, root_key);
    if ( 0 == ret )
        ret = tls_clt_init(&tls.clt);

    return ret;
}


/*
 * 初始化 tls server 端
 */
static int tls_srv_init(tls_srv *srv, const char *root_crt, const char *root_key) {
    int ret;

    mbedtls_x509_crt_init(&srv->root_crt);
    mbedtls_pk_init(&srv->root_key);

    mbedtls_ssl_config_init(&srv->conf);
    mbedtls_entropy_init(&srv->entropy);
    mbedtls_ctr_drbg_init(&srv->ctr_drbg);
    mbedtls_ssl_cache_init(&srv->cache);
    mbedtls_ssl_ticket_init(&srv->ticket_ctx);

    mbedtls_ssl_conf_dbg(&srv->conf, tls_debug_out, stdout);

//     - 0 No debug
//     - 1 Error
//     - 2 State change
//     - 3 Informational
//     - 4 Verbose
    mbedtls_debug_set_threshold(0);

    ret = mbedtls_ctr_drbg_seed(
        &srv->ctr_drbg,
        mbedtls_entropy_func,
        &srv->entropy,
        NULL,
        0
    );
    BREAK_ON_FAILURE(ret);

    ret = mbedtls_x509_crt_parse_file(&srv->root_crt, root_crt);
    BREAK_ON_FAILURE(ret);

    ret = mbedtls_pk_parse_keyfile(&srv->root_key, root_key, NULL);
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
static int tls_clt_init(tls_clt *clt) {
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

static void tls_clear(void) {
    /* srv */
    mbedtls_x509_crt_free(&tls.srv.root_crt);
    mbedtls_pk_free(&tls.srv.root_key);
    mbedtls_ssl_config_free(&tls.srv.conf);
    mbedtls_entropy_free(&tls.srv.entropy);
    mbedtls_ctr_drbg_free(&tls.srv.ctr_drbg);
    mbedtls_ssl_cache_free(&tls.srv.cache);
    mbedtls_ssl_ticket_free(&tls.srv.ticket_ctx);
    mbedtls_pk_free(&tls.srv.mykey);

    /* clt */
    mbedtls_ssl_config_free(&tls.clt.conf);
    mbedtls_entropy_free(&tls.clt.entropy);
    mbedtls_ctr_drbg_free(&tls.clt.ctr_drbg);
}

static void tls_debug_out(
    // ReSharper disable once CppParameterMayBeConstPtrOrRef
    void *ctx, int level,
    // ReSharper disable once CppParameterMayBeConst
    const char *file, int line,
    const char *str) {

//    mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
//    fflush((FILE *)ctx);

    int lv = -1;

    switch ( level ) {
    case 0:
        break;
    case 1:
        lv = LOG_ERROR;
        break;
    case 2:
        lv = LOG_KEY;
        break;
    case 3:
        lv = LOG_INFO;
        break;
    case 4:
        lv = LOG_DEBUG;
        break;
    default:
        break;
    }

    (void)ctx;
    if ( -1 != lv)
        tlsflat_on_msg(lv, "%s:%04d: %s", file, line, str);
}
