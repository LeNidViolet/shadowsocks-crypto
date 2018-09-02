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
#include "mbedtls/cipher.h"
#include "shadowsocks-netio/shadowsocks-netio.h"
#include "internal.h"

static unsigned int ssn_outstanding = 0;
static unsigned int dsn_outstanding = 0;

static unsigned char crypto_space[MAX_SS_TCP_FRAME_LEN];
static mbedtls_cipher_context_t encrypt_dgram_ctx;
static mbedtls_cipher_context_t decrypt_dgram_ctx;

typedef struct {
    mbedtls_cipher_context_t encrypt_ctx;
    mbedtls_cipher_context_t decrypt_ctx;
    unsigned char iv_encrypt[MAX_CRYPTO_SALT_LEN];
    unsigned char iv_decrypt[MAX_CRYPTO_SALT_LEN];
    int first_encrypt;
    int first_decrypt;

    void *ctx;
} STREAM_SESSION;

typedef struct {

    void *ctx;
} DGRAM_SESSION;


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


int init_calback_unit(void) {
    init_cipher(&encrypt_dgram_ctx, MBEDTLS_ENCRYPT);
    init_cipher(&decrypt_dgram_ctx, MBEDTLS_DECRYPT);

    return 0;
}

void free_callback_unit(void) {
    mbedtls_cipher_free(&encrypt_dgram_ctx);
    mbedtls_cipher_free(&decrypt_dgram_ctx);
}


void sscrypto_on_msg(int level, const char *msg) {
    if ( CryptoEnv.ori_cbs.on_msg ) {
        CryptoEnv.ori_cbs.on_msg(level, msg);
    }
}

void sscrypto_on_bind(const char *host, unsigned short port) {
    if ( CryptoEnv.ori_cbs.on_bind ) {
        CryptoEnv.ori_cbs.on_bind(host, port);
    }
}

void sscrypto_on_stream_connection_made(ADDRESS_PAIR *addr, void *ctx) {
    STREAM_SESSION *ssn;

    if ( CryptoEnv.ori_cbs.on_stream_connection_made ) {
        ssn = (STREAM_SESSION *)ctx;
        CHECK(ssn);

        CryptoEnv.ori_cbs.on_stream_connection_made(addr, ssn->ctx);
    }
}

void sscrypto_on_new_stream(ADDRESS *addr, void **ctx, void *stream_id) {
    STREAM_SESSION *ssn;

    ENSURE((ssn = malloc(sizeof(*ssn))) != NULL);
    memset(ssn, 0, sizeof(*ssn));

    init_cipher(&ssn->encrypt_ctx, MBEDTLS_ENCRYPT);
    init_cipher(&ssn->decrypt_ctx, MBEDTLS_DECRYPT);
    ssn->first_encrypt = 1;
    ssn->first_decrypt = 1;

    *ctx = ssn;
    if ( CryptoEnv.ori_cbs.on_new_stream ) {
        CryptoEnv.ori_cbs.on_new_stream(addr, &ssn->ctx, stream_id);
    }

    ssn_outstanding++;
}

void sscrypto_on_stream_teardown(void *ctx) {
    STREAM_SESSION *ssn;
    ssn = (STREAM_SESSION *)ctx;
    CHECK(ssn);

    if ( CryptoEnv.ori_cbs.on_stream_teardown ) {
        CryptoEnv.ori_cbs.on_stream_teardown(ssn->ctx);
    }

    mbedtls_cipher_free(&ssn->encrypt_ctx);
    mbedtls_cipher_free(&ssn->decrypt_ctx);

    if ( DEBUG_CHECKS )
        memset(ssn, -1, sizeof(*ssn));

    free(ssn);

    ssn_outstanding--;
}

void sscrypto_on_new_dgram(ADDRESS_PAIR *addr, void **ctx) {
    DGRAM_SESSION *dsn;

    ENSURE((dsn = malloc(sizeof(*dsn))) != NULL);
    memset(dsn, 0, sizeof(*dsn));

    *ctx = dsn;
    if ( CryptoEnv.ori_cbs.on_new_dgram ) {
        CryptoEnv.ori_cbs.on_new_dgram(addr, &dsn->ctx);
    }

    dsn_outstanding++;
}

void sscrypto_on_dgram_teardown(void *ctx) {
    DGRAM_SESSION *dsn;
    dsn = (DGRAM_SESSION *)ctx;
    CHECK(dsn);

    if ( CryptoEnv.ori_cbs.on_dgram_teardown ) {
        CryptoEnv.ori_cbs.on_dgram_teardown(dsn->ctx);
    }

    if ( DEBUG_CHECKS )
        memset(dsn, -1, sizeof(*dsn));

    free(dsn);

    dsn_outstanding--;
}

int sscrypto_on_plain_stream(MEM_RANGE *buf, int direct, void *ctx) {
    STREAM_SESSION *ssn;
    int action = PASS;

    if ( CryptoEnv.ori_cbs.on_plain_stream ) {
        ssn = (STREAM_SESSION *)ctx;
        CHECK(ssn);

        action = CryptoEnv.ori_cbs.on_plain_stream(buf, direct, ssn->ctx);
    }

    return action;
}

void sscrypto_on_plain_dgram(MEM_RANGE *buf, int direct, void *ctx) {
    DGRAM_SESSION *dsn;

    if ( CryptoEnv.ori_cbs.on_plain_dgram ) {
        dsn = (DGRAM_SESSION *)ctx;
        CHECK(dsn);

        CryptoEnv.ori_cbs.on_plain_dgram(buf, direct, dsn->ctx);
    }
}

int sscrypto_on_stream_encrypt(MEM_RANGE *buf, void *ctx) {
    int ret;
    size_t encrypt_len, iv_len;
    unsigned char *pos;
    STREAM_SESSION *ssn;

    CHECK(buf->data_len <= sizeof(crypto_space));

    ssn = (STREAM_SESSION *)ctx;
    iv_len = CryptoEnv.method->iv_len;

    if ( ssn->first_encrypt ) {
        const char *seed = "seed name here";

        ret = gen_iv(seed, ssn->iv_encrypt, iv_len);
        BREAK_ON_FAILURE(ret);

        ret = mbedtls_cipher_set_iv(
            &ssn->encrypt_ctx,
            (const unsigned char*)ssn->iv_encrypt,
            iv_len);
        BREAK_ON_FAILURE(ret);
    }

    encrypt_len = buf->data_len;
    if ( ssn->first_encrypt ) {
        encrypt_len += iv_len;
    }
    CHECK(encrypt_len <= buf->buf_len);

    pos = crypto_space;

    if ( ssn->first_encrypt ) {
        memcpy(pos, ssn->iv_encrypt, iv_len);
        pos += iv_len;
        encrypt_len -= iv_len;
    }

    ret = mbedtls_cipher_update(
        &ssn->encrypt_ctx,
        (const unsigned char*)buf->data_base,
        buf->data_len,
        pos,
        &encrypt_len);
    BREAK_ON_FAILURE(ret);
    CHECK(buf->data_len == encrypt_len);

    if ( ssn->first_encrypt ) {
        encrypt_len += iv_len;
        ssn->first_encrypt = 0;
    }

    memcpy(buf->buf_base, crypto_space, encrypt_len);
    buf->data_base = buf->buf_base;
    buf->data_len = encrypt_len;

BREAK_LABEL:

    return ret;
}

int sscrypto_on_stream_decrypt(MEM_RANGE *buf, void *ctx) {
    int ret = -1;
    char *pos;
    size_t ret_len, decrypt_len, iv_len;
    STREAM_SESSION *ssn;

    CHECK(buf->data_len <= sizeof(crypto_space));

    ssn = (STREAM_SESSION *)ctx;
    iv_len = CryptoEnv.method->iv_len;

    if ( ssn->first_decrypt ) {
        if ( buf->data_len < iv_len )
            BREAK_NOW;

        memcpy(ssn->iv_decrypt, buf->data_base, iv_len);
        ret = mbedtls_cipher_set_iv(
            &ssn->decrypt_ctx,
            ssn->iv_decrypt,
            iv_len);
        BREAK_ON_FAILURE(ret);
    }

    decrypt_len = buf->data_len;

    pos = buf->data_base;
    if ( ssn->first_decrypt ) {
        pos += iv_len;
        decrypt_len -= iv_len;
    }

    ret = mbedtls_cipher_update(
        &ssn->decrypt_ctx,
        (const unsigned char *)pos,
        decrypt_len,
        crypto_space,
        &ret_len);
    BREAK_ON_FAILURE(ret);
    CHECK(ret_len == decrypt_len);

    memcpy(buf->buf_base, crypto_space, decrypt_len);
    buf->data_base = buf->buf_base;
    buf->data_len = decrypt_len;

    if ( ssn->first_decrypt )
        ssn->first_decrypt = 0;

BREAK_LABEL:

    return ret;
}

int sscrypto_on_dgram_encrypt(MEM_RANGE *buf) {
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

    return ret;
}

int sscrypto_on_dgram_decrypt(MEM_RANGE *buf) {
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

    return ret;
}
