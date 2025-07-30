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
#include <stdarg.h>
#include <memory.h>
#include "mbedtls/platform.h"
#include "mbedtls/cipher.h"
#include "internal.h"

static unsigned int ssn_outstanding = 0;
static unsigned int dsn_outstanding = 0;

static unsigned char crypto_space[256 * 1024 + MAX_SS_TCP_WRAPPER_LEN];  /* 加密解密缓冲区 */
static mbedtls_cipher_context_t encrypt_dgram_ctx;                      /* UDP加密环境CTX */
static mbedtls_cipher_context_t decrypt_dgram_ctx;                      /* UDP解密环境CTX */


/* TCP流CONTEXT */
typedef struct {
    int index;
    int connected;                                                      /* 是否连接上 */

    mbedtls_cipher_context_t encrypt_ctx;                               /* 每个TCP流都有自己的加密解密环境CTX */
    mbedtls_cipher_context_t decrypt_ctx;

    unsigned char iv_encrypt[MAX_CRYPTO_SALT_LEN];
    unsigned char iv_decrypt[MAX_CRYPTO_SALT_LEN];

    int first_encrypt;                                                  /* 首次加密解密操作略有不同 */
    int first_decrypt;

    int is_tls;                                                         /* 是否是TLS流 */
    void *tls_ctx;                                                      /* TLSFLAT使用的环境CTX */
    void *stream_id;                                                    /* 透明数据,回调时使用 */
} STREAM_SESSION_CRYP;


/* UDP流CONTEXT */
typedef struct {
    int index;
} DGRAM_SESSION_CRYP;


extern crypto_env shadowsocks_env;

static void init_cipher(mbedtls_cipher_context_t *ctx, int mode) {
    const mbedtls_cipher_info_t *info;

    mbedtls_cipher_init(ctx);
    info = mbedtls_cipher_info_from_type(shadowsocks_env.method->type);
    CHECK(info);
    CHECK(0 == mbedtls_cipher_setup(ctx, info));
    CHECK(0 == mbedtls_cipher_setkey(
        ctx,
        shadowsocks_env.key,
        8 * shadowsocks_env.method->key_len,
        mode));
}

int init_crypt_unit(void) {
    init_cipher(&encrypt_dgram_ctx, MBEDTLS_ENCRYPT);
    init_cipher(&decrypt_dgram_ctx, MBEDTLS_DECRYPT);

    return 0;
}

void free_crypt_unit(void) {
    mbedtls_cipher_free(&encrypt_dgram_ctx);
    mbedtls_cipher_free(&decrypt_dgram_ctx);
}


void sscrypto_on_msg(int level, const char *format, ...) {
    va_list ap;
    char msg[1024];

    va_start(ap, format);
    vsnprintf(msg, sizeof(msg), format, ap);
    va_end(ap);

    if ( shadowsocks_env.callbacks.on_msg ) {
        shadowsocks_env.callbacks.on_msg(level, msg);
    }
}

void sscrypto_on_bind(const char *host, unsigned short port) {
    if ( shadowsocks_env.callbacks.on_bind ) {
        shadowsocks_env.callbacks.on_bind(host, port);
    }
}

void sscrypto_on_new_stream(const ADDRESS *addr, void **ctx, void *stream_id) {
    static int stream_index = 0;
    STREAM_SESSION_CRYP *session;

    (void)addr;

    ENSURE((session = mbedtls_calloc(1, sizeof(*session))) != NULL);
    memset(session, 0, sizeof(*session));

    init_cipher(&session->encrypt_ctx, MBEDTLS_ENCRYPT);
    init_cipher(&session->decrypt_ctx, MBEDTLS_DECRYPT);
    session->first_encrypt = 1;
    session->first_decrypt = 1;
    session->is_tls = 0;
    session->stream_id = stream_id;
    session->index = stream_index++;
    session->connected = 0;

    *ctx = session;

    ssn_outstanding++;
}

void sscrypto_on_stream_connection_made(address_pair *addr, void *ctx) {
    STREAM_SESSION_CRYP *session;

    session = (STREAM_SESSION_CRYP *)ctx;
    CHECK(session);

    if ( 443 == addr->remote->port ) {              /* 如果是TLS流, 通知TLSFLAT */
        session->is_tls = 1;
        tlsflat_on_stream_connection_made(addr, session->stream_id, session, &session->tls_ctx);
    }

    if ( shadowsocks_env.callbacks.on_stream_connection_made ) {
        shadowsocks_env.callbacks.on_stream_connection_made(
            addr->local->domain,
            addr->local->ip,
            addr->local->port,
            addr->remote->domain,
            addr->remote->ip,
            addr->remote->port,
            session->index
            );
    }

    session->connected = 1;
}

void sscrypto_on_stream_teardown(void *ctx) {
    STREAM_SESSION_CRYP *session;
    session = (STREAM_SESSION_CRYP *)ctx;
    CHECK(session);

    if ( session->is_tls ) {
        tlsflat_on_stream_teardown(session->tls_ctx);
    }

    if ( shadowsocks_env.callbacks.on_stream_teardown ) {
        /* 如果链接未链接上 不用继续向上调用 */
        if ( session->connected ) {
            shadowsocks_env.callbacks.on_stream_teardown(session->index);
        }
    }

    mbedtls_cipher_free(&session->encrypt_ctx);
    mbedtls_cipher_free(&session->decrypt_ctx);

    if ( DEBUG_CHECKS )
        memset(session, -1, sizeof(*session));

    mbedtls_free(session);

    ssn_outstanding--;
}

void sscrypto_on_new_dgram(const address_pair *addr, void **ctx) {
    static int dgram_index = 0;
    DGRAM_SESSION_CRYP *session;

    ENSURE((session = mbedtls_calloc(1, sizeof(*session))) != NULL);
    memset(session, 0, sizeof(*session));

    session->index = dgram_index++;

    *ctx = session;
    if ( shadowsocks_env.callbacks.on_dgram_connection_made ) {
        shadowsocks_env.callbacks.on_dgram_connection_made(
            addr->local->domain,
            addr->local->ip,
            addr->local->port,
            addr->remote->domain,
            addr->remote->ip,
            addr->remote->port,
            session->index
            );
    }

    dsn_outstanding++;
}

void sscrypto_on_dgram_teardown(void *ctx) {
    DGRAM_SESSION_CRYP *session;
    session = (DGRAM_SESSION_CRYP *)ctx;
    CHECK(session);

    if ( shadowsocks_env.callbacks.on_dgram_teardown ) {
        shadowsocks_env.callbacks.on_dgram_teardown(session->index);
    }

    if ( DEBUG_CHECKS )
        memset(session, -1, sizeof(*session));

    mbedtls_free(session);

    dsn_outstanding--;
}

int sscrypto_on_plain_stream(const BUF_RANGE *buf, int direct, void *ctx) {
    STREAM_SESSION_CRYP *session;
    int action = PASS;

    session = (STREAM_SESSION_CRYP *)ctx;
    CHECK(session);

    /* 如果是 TLS 数据流, 等待 TLS 解密的回调中再向上通报数据 (sscrypto_tls_on_plain_stream) */
    if ( session->is_tls ) {
        action = tlsflat_on_plain_stream(buf, direct, session->tls_ctx);
        BREAK_NOW;
    }

    if ( shadowsocks_env.callbacks.on_plain_stream ) {
        shadowsocks_env.callbacks.on_plain_stream(
            buf->data_base,
            buf->data_len,
            STREAM_UP == direct,
            session->index
            );
    }

BREAK_LABEL:

    return action;
}

/* 由TLSFLAT解密数据之后调用至此 */
void sscrypto_tls_on_plain_stream(const char *data, size_t data_len, int direct, void *ss_ctx) {
    STREAM_SESSION_CRYP *session;

    session = (STREAM_SESSION_CRYP *)ss_ctx;
    CHECK(session);

    if ( shadowsocks_env.callbacks.on_plain_stream ) {
        shadowsocks_env.callbacks.on_plain_stream(
            data,
            data_len,
            STREAM_UP == direct,
            session->index
            );
    }
}

void sscrypto_on_plain_dgram(const BUF_RANGE *buf, int direct, void *ctx) {
    DGRAM_SESSION_CRYP *session;

    session = (DGRAM_SESSION_CRYP *)ctx;
    CHECK(session);

    if ( shadowsocks_env.callbacks.on_plain_dgram ) {
        shadowsocks_env.callbacks.on_plain_dgram(
            buf->data_base,
            buf->data_len,
            STREAM_UP == direct,
            session->index);
    }
}

int sscrypto_on_stream_encrypt(BUF_RANGE *buf, void *ctx) {
    int ret;
    size_t encrypt_len, iv_len;
    unsigned char *pos;
    STREAM_SESSION_CRYP *session;

    CHECK(buf->data_len <= sizeof(crypto_space));

    session = (STREAM_SESSION_CRYP *)ctx;
    iv_len = shadowsocks_env.method->iv_len;

    if ( session->first_encrypt ) {
        const char *seed = "seed name here";

        /* 首个数据包需要生成IV */
        ret = gen_iv(seed, session->iv_encrypt, iv_len);
        BREAK_ON_FAILURE(ret);

        ret = mbedtls_cipher_set_iv(
            &session->encrypt_ctx,
            (const unsigned char*)session->iv_encrypt,
            iv_len);
        BREAK_ON_FAILURE(ret);
    }

    pos = crypto_space;
    encrypt_len = buf->data_len;

    if ( session->first_encrypt ) {
        encrypt_len += iv_len;
    }
    CHECK(encrypt_len <= buf->buf_len);

    if ( session->first_encrypt ) {
        /* 填写IV */
        memcpy(pos, session->iv_encrypt, iv_len);
        pos += iv_len;
        encrypt_len -= iv_len;
    }

    ret = mbedtls_cipher_update(
        &session->encrypt_ctx,
        (const unsigned char*)buf->data_base,
        buf->data_len,
        pos,
        &encrypt_len);
    BREAK_ON_FAILURE(ret);
    CHECK(buf->data_len == encrypt_len);

    if ( session->first_encrypt ) {
        encrypt_len += iv_len;
        session->first_encrypt = 0;
    }

    memcpy(buf->buf_base, crypto_space, encrypt_len);
    buf->data_base = buf->buf_base;
    buf->data_len = encrypt_len;

BREAK_LABEL:

    return ret;
}

int sscrypto_on_stream_decrypt(BUF_RANGE *buf, void *ctx) {
    int ret = -1;
    char *pos;
    size_t ret_len, decrypt_len, iv_len;
    STREAM_SESSION_CRYP *session;

    CHECK(buf->data_len <= sizeof(crypto_space));

    session = (STREAM_SESSION_CRYP *)ctx;
    iv_len = shadowsocks_env.method->iv_len;

    if ( session->first_decrypt ) {
        if ( buf->data_len < iv_len )
            BREAK_NOW;

        /* 首个数据包最前面是IV */
        memcpy(session->iv_decrypt, buf->data_base, iv_len);
        ret = mbedtls_cipher_set_iv(
            &session->decrypt_ctx,
            session->iv_decrypt,
            iv_len);
        BREAK_ON_FAILURE(ret);
    }

    pos = buf->data_base;
    decrypt_len = buf->data_len;

    if ( session->first_decrypt ) {
        /* 越过IV部分 */
        pos += iv_len;
        decrypt_len -= iv_len;
    }

    ret = mbedtls_cipher_update(
        &session->decrypt_ctx,
        (const unsigned char *)pos,
        decrypt_len,
        crypto_space,
        &ret_len);
    BREAK_ON_FAILURE(ret);
    CHECK(ret_len == decrypt_len);

    memcpy(buf->buf_base, crypto_space, decrypt_len);
    buf->data_base = buf->buf_base;
    buf->data_len = decrypt_len;

    if ( session->first_decrypt )
        session->first_decrypt = 0;

BREAK_LABEL:

    return ret;
}

int sscrypto_on_dgram_encrypt(BUF_RANGE *buf) {
    int ret;
    unsigned char iv_encrypt[MAX_CRYPTO_SALT_LEN];
    size_t iv_len;
    const char *pers = "seed name here";
    size_t encrypt_len;
    unsigned char *pos;

    iv_len = shadowsocks_env.method->iv_len;
    ret = gen_iv(pers, iv_encrypt, iv_len);
    BREAK_ON_FAILURE(ret);

    ret = mbedtls_cipher_set_iv(
        &encrypt_dgram_ctx,
        iv_encrypt,
        iv_len);
    BREAK_ON_FAILURE(ret);

    ret = mbedtls_cipher_reset(&encrypt_dgram_ctx);
    BREAK_ON_FAILURE(ret);

    encrypt_len = buf->data_len;
    encrypt_len += iv_len;
    CHECK(encrypt_len <= buf->buf_len);

    pos = crypto_space;
    memcpy(pos, iv_encrypt, iv_len);
    pos += iv_len;
    encrypt_len -= iv_len;

    ret = mbedtls_cipher_update(
        &encrypt_dgram_ctx,
        (const unsigned char*)buf->data_base,
        buf->data_len,
        pos,
        &encrypt_len);
    BREAK_ON_FAILURE(ret);
    CHECK(buf->data_len == encrypt_len);

    encrypt_len += iv_len;
    memcpy(buf->buf_base, crypto_space, encrypt_len);
    buf->data_base = buf->buf_base;
    buf->data_len = encrypt_len;

BREAK_LABEL:

    return ret;
}

int sscrypto_on_dgram_decrypt(BUF_RANGE *buf) {
    int ret;
    size_t decrypt_len, ret_len, iv_len;
    char *pos;
    char iv_decrypt[MAX_CRYPTO_SALT_LEN];

    iv_len = shadowsocks_env.method->iv_len;

    memcpy(iv_decrypt, buf->buf_base, iv_len);

    ret = mbedtls_cipher_set_iv(
        &decrypt_dgram_ctx,
        (const unsigned char *)iv_decrypt,
        iv_len);
    BREAK_ON_FAILURE(ret);

    ret = mbedtls_cipher_reset(&decrypt_dgram_ctx);
    BREAK_ON_FAILURE(ret);

    pos = buf->buf_base + iv_len;
    decrypt_len = buf->data_len - iv_len;

    ret = mbedtls_cipher_update(
        &decrypt_dgram_ctx,
        (const unsigned char *)pos,
        decrypt_len,
        crypto_space,
        &ret_len);
    BREAK_ON_FAILURE(ret);
    CHECK(decrypt_len == ret_len);

    memcpy(buf->buf_base, crypto_space, decrypt_len);
    buf->data_base = buf->buf_base;
    buf->data_len = decrypt_len;

BREAK_LABEL:

    return ret;
}
