/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/14.
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
#include <memory.h>
#include "mbedtls/platform.h"
#include "mbedtls/cipher.h"
#include "internal.h"

static unsigned int ssn_outstanding = 0;
static unsigned int dsn_outstanding = 0;

static unsigned char crypto_space[16 * 1024 + MAX_SS_TCP_WRAPPER_LEN];  /* 加密解密缓冲区 */
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


extern CRYPTO_ENV CryptoEnv;

static void init_cipher(mbedtls_cipher_context_t *ctx, int mode) {
    const mbedtls_cipher_info_t *info;

    mbedtls_cipher_init(ctx);
    info = mbedtls_cipher_info_from_type(CryptoEnv.method->type);
    CHECK(info);
    CHECK(0 == mbedtls_cipher_setup(ctx, info));
    CHECK(0 == mbedtls_cipher_setkey(
        ctx,
        CryptoEnv.key,
        8 * CryptoEnv.method->key_len,
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


void sscrypto_on_msg(int level, const char *msg) {
    if ( CryptoEnv.callbacks.on_msg ) {
        CryptoEnv.callbacks.on_msg(level, msg);
    }
}

void sscrypto_on_bind(const char *host, unsigned short port) {
    if ( CryptoEnv.callbacks.on_bind ) {
        CryptoEnv.callbacks.on_bind(host, port);
    }
}

void sscrypto_on_new_stream(const address *addr, void **ctx, void *stream_id) {
    static int stream_index = 0;
    STREAM_SESSION_CRYP *ss;

    (void)addr;

    ENSURE((ss = mbedtls_calloc(1, sizeof(*ss))) != NULL);
    memset(ss, 0, sizeof(*ss));

    init_cipher(&ss->encrypt_ctx, MBEDTLS_ENCRYPT);
    init_cipher(&ss->decrypt_ctx, MBEDTLS_DECRYPT);
    ss->first_encrypt = 1;
    ss->first_decrypt = 1;
    ss->is_tls = 0;
    ss->stream_id = stream_id;
    ss->index = stream_index++;
    ss->connected = 0;

    *ctx = ss;

    ssn_outstanding++;
}

void sscrypto_on_stream_connection_made(address_pair *addr, void *ctx) {
    STREAM_SESSION_CRYP *ss;

    ss = (STREAM_SESSION_CRYP *)ctx;
    CHECK(ss);

    if ( 443 == addr->remote->port ) {              /* 如果是TLS流, 通知TLSFLAT */
        ss->is_tls = 1;
        tlsflat_on_stream_connection_made(addr, ss->stream_id, ss, &ss->tls_ctx);
    }

    if ( CryptoEnv.callbacks.on_stream_connection_made ) {
        CryptoEnv.callbacks.on_stream_connection_made(
            addr->local->host,
            addr->local->port,
            addr->remote->host,
            addr->remote->port,
            ss->index
            );
    }

    ss->connected = 1;
}

void sscrypto_on_stream_teardown(void *ctx) {
    STREAM_SESSION_CRYP *ss;
    ss = (STREAM_SESSION_CRYP *)ctx;
    CHECK(ss);

    if ( ss->is_tls ) {
        tlsflat_on_stream_teardown(ss->tls_ctx);
    }

    if ( CryptoEnv.callbacks.on_stream_teardown ) {
        /* 如果链接未链接上 不用继续向上调用 */
        if ( ss->connected ) {
            CryptoEnv.callbacks.on_stream_teardown(ss->index);
        }
    }

    mbedtls_cipher_free(&ss->encrypt_ctx);
    mbedtls_cipher_free(&ss->decrypt_ctx);

    if ( DEBUG_CHECKS )
        memset(ss, -1, sizeof(*ss));

    mbedtls_free(ss);

    ssn_outstanding--;
}

void sscrypto_on_new_dgram(const address_pair *addr, void **ctx) {
    static int dgram_index = 0;
    DGRAM_SESSION_CRYP *ds;

    ENSURE((ds = mbedtls_calloc(1, sizeof(*ds))) != NULL);
    memset(ds, 0, sizeof(*ds));

    ds->index = dgram_index++;

    *ctx = ds;
    if ( CryptoEnv.callbacks.on_dgram_connection_made ) {
        CryptoEnv.callbacks.on_dgram_connection_made(
            addr->local->host,
            addr->local->port,
            addr->remote->host,
            addr->remote->port,
            ds->index
            );
    }

    dsn_outstanding++;
}

void sscrypto_on_dgram_teardown(void *ctx) {
    DGRAM_SESSION_CRYP *ds;
    ds = (DGRAM_SESSION_CRYP *)ctx;
    CHECK(ds);

    if ( CryptoEnv.callbacks.on_dgram_teardown ) {
        CryptoEnv.callbacks.on_dgram_teardown(ds->index);
    }

    if ( DEBUG_CHECKS )
        memset(ds, -1, sizeof(*ds));

    mbedtls_free(ds);

    dsn_outstanding--;
}

int sscrypto_on_plain_stream(const buf_range *buf, int direct, void *ctx) {
    STREAM_SESSION_CRYP *ss;
    int action = PASS;

    ss = (STREAM_SESSION_CRYP *)ctx;
    CHECK(ss);

    /* 如果是 TLS 数据流, 等待 TLS 解密的回调中再向上通报数据 (sscrypto_tls_on_plain_stream) */
    if ( ss->is_tls ) {
        action = tlsflat_on_plain_stream(buf, direct, ss->tls_ctx);
        BREAK_NOW;
    }

    if ( CryptoEnv.callbacks.on_plain_stream ) {
        CryptoEnv.callbacks.on_plain_stream(buf->data_base, buf->data_len, direct, ss->index);
    }

BREAK_LABEL:

    return action;
}

/* 由TLSFLAT解密数据之后调用至此 */
void sscrypto_tls_on_plain_stream(const char *data, size_t data_len, int direct, void *ss_ctx) {
    STREAM_SESSION_CRYP *ss;

    ss = (STREAM_SESSION_CRYP *)ss_ctx;
    CHECK(ss);

    if ( CryptoEnv.callbacks.on_plain_stream ) {
        CryptoEnv.callbacks.on_plain_stream(data, data_len, direct, ss->index);
    }
}

void sscrypto_on_plain_dgram(const buf_range *buf, int direct, void *ctx) {
    DGRAM_SESSION_CRYP *ds;

    ds = (DGRAM_SESSION_CRYP *)ctx;
    CHECK(ds);

    if ( CryptoEnv.callbacks.on_plain_dgram ) {
        CryptoEnv.callbacks.on_plain_dgram(buf->data_base, buf->data_len, direct, ds->index);
    }
}

int sscrypto_on_stream_encrypt(buf_range *buf, void *ctx) {
    int ret;
    size_t encrypt_len, iv_len;
    unsigned char *pos;
    STREAM_SESSION_CRYP *ss;

    CHECK(buf->data_len <= sizeof(crypto_space));

    ss = (STREAM_SESSION_CRYP *)ctx;
    iv_len = CryptoEnv.method->iv_len;

    if ( ss->first_encrypt ) {
        const char *seed = "seed name here";

        /* 首个数据包需要生成IV */
        ret = gen_iv(seed, ss->iv_encrypt, iv_len);
        BREAK_ON_FAILURE(ret);

        ret = mbedtls_cipher_set_iv(
            &ss->encrypt_ctx,
            (const unsigned char*)ss->iv_encrypt,
            iv_len);
        BREAK_ON_FAILURE(ret);
    }

    pos = crypto_space;
    encrypt_len = buf->data_len;

    if ( ss->first_encrypt ) {
        encrypt_len += iv_len;
    }
    CHECK(encrypt_len <= buf->buf_len);

    if ( ss->first_encrypt ) {
        /* 填写IV */
        memcpy(pos, ss->iv_encrypt, iv_len);
        pos += iv_len;
        encrypt_len -= iv_len;
    }

    ret = mbedtls_cipher_update(
        &ss->encrypt_ctx,
        (const unsigned char*)buf->data_base,
        buf->data_len,
        pos,
        &encrypt_len);
    BREAK_ON_FAILURE(ret);
    CHECK(buf->data_len == encrypt_len);

    if ( ss->first_encrypt ) {
        encrypt_len += iv_len;
        ss->first_encrypt = 0;
    }

    memcpy(buf->buf_base, crypto_space, encrypt_len);
    buf->data_base = buf->buf_base;
    buf->data_len = encrypt_len;

BREAK_LABEL:

    if ( 0 != ret) {
        sscrypto_on_msg(1, "Stream Encrypt Failed");
    }

    return ret;
}

int sscrypto_on_stream_decrypt(buf_range *buf, void *ctx) {
    int ret = -1;
    char *pos;
    size_t ret_len, decrypt_len, iv_len;
    STREAM_SESSION_CRYP *ss;

    CHECK(buf->data_len <= sizeof(crypto_space));

    ss = (STREAM_SESSION_CRYP *)ctx;
    iv_len = CryptoEnv.method->iv_len;

    if ( ss->first_decrypt ) {
        if ( buf->data_len < iv_len )
            BREAK_NOW;

        /* 首个数据包最前面是IV */
        memcpy(ss->iv_decrypt, buf->data_base, iv_len);
        ret = mbedtls_cipher_set_iv(
            &ss->decrypt_ctx,
            ss->iv_decrypt,
            iv_len);
        BREAK_ON_FAILURE(ret);
    }

    pos = buf->data_base;
    decrypt_len = buf->data_len;

    if ( ss->first_decrypt ) {
        /* 越过IV部分 */
        pos += iv_len;
        decrypt_len -= iv_len;
    }

    ret = mbedtls_cipher_update(
        &ss->decrypt_ctx,
        (const unsigned char *)pos,
        decrypt_len,
        crypto_space,
        &ret_len);
    BREAK_ON_FAILURE(ret);
    CHECK(ret_len == decrypt_len);

    memcpy(buf->buf_base, crypto_space, decrypt_len);
    buf->data_base = buf->buf_base;
    buf->data_len = decrypt_len;

    if ( ss->first_decrypt )
        ss->first_decrypt = 0;

BREAK_LABEL:

    if ( 0 != ret) {
        sscrypto_on_msg(1, "Stream Decrypt Failed");
    }

    return ret;
}

int sscrypto_on_dgram_encrypt(buf_range *buf) {
    int ret;
    unsigned char iv_encrypt[MAX_CRYPTO_SALT_LEN];
    size_t iv_len;
    const char *pers = "seed name here";
    size_t encrypt_len;
    unsigned char *pos;

    iv_len = CryptoEnv.method->iv_len;
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

    if ( 0 != ret) {
        sscrypto_on_msg(1, "Dgram Encrypt Failed");
    }

    return ret;
}

int sscrypto_on_dgram_decrypt(buf_range *buf) {
    int ret;
    size_t decrypt_len, ret_len, iv_len;
    char *pos;
    char iv_decrypt[MAX_CRYPTO_SALT_LEN];

    iv_len = CryptoEnv.method->iv_len;

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

    if ( 0 != ret) {
        sscrypto_on_msg(1, "Dgram Decrypt Failed");
    }

    return ret;
}
