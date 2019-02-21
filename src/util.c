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
#include <string.h>
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md5.h"
#include "internal.h"

/* TODO: ADD AEAD CIPHER METHODS */

static const CRYPTO_INFO Methods[] = {
    {MBEDTLS_CIPHER_AES_128_CFB128, "AES-128-CFB128", "AES-128-CFB", 16, 16},
    {MBEDTLS_CIPHER_AES_192_CFB128, "AES-192-CFB128", "AES-192-CFB", 24, 16},
    {MBEDTLS_CIPHER_AES_256_CFB128, "AES-256-CFB128", "AES-256-CFB", 32, 16},
    {MBEDTLS_CIPHER_AES_128_CTR, "AES-128-CTR", "AES-128-CTR", 16, 16},
    {MBEDTLS_CIPHER_AES_192_CTR, "AES-192-CTR", "AES-192-CTR", 24, 16},
    {MBEDTLS_CIPHER_AES_256_CTR, "AES-256-CTR", "AES-256-CTR", 32, 16},
    {MBEDTLS_CIPHER_CAMELLIA_128_CFB128, "CAMELLIA-128-CFB128", "CAMELLIA-128-CFB", 16, 16},
    {MBEDTLS_CIPHER_CAMELLIA_192_CFB128, "CAMELLIA-192-CFB128", "CAMELLIA-192-CFB", 24, 16},
    {MBEDTLS_CIPHER_CAMELLIA_256_CFB128, "CAMELLIA-256-CFB128", "CAMELLIA-256-CFB", 32, 16},
};
static unsigned int Methods_Count = sizeof(Methods) / sizeof(Methods[0]);

/* Compatible with shadowsocks */
int gen_key(const char *seed, unsigned char *key, size_t key_len) {
    int ret = -1;
    unsigned char digest[16];
    size_t seed_len;
    unsigned char *buf = NULL;
    size_t buf_len;
    unsigned char *pos = NULL;
    size_t rm_len, update_len, cpy_len = 0;

    BREAK_ON_NULL(seed);
    BREAK_ON_NULL(key);
    BREAK_ON_NULL(key_len);

    seed_len = strlen(seed);
    buf_len = seed_len + sizeof(digest);
    buf = mbedtls_calloc(1, buf_len);
    BREAK_ON_NULL(buf);

    rm_len = key_len;
    while ( rm_len ) {
        if ( pos ) {
            memcpy(buf, pos, sizeof(digest));
            memcpy(buf + sizeof(digest), seed, seed_len);
            update_len = buf_len;
            pos += cpy_len;
        } else {
            memcpy(buf, seed, seed_len);
            update_len = seed_len;
            pos = key;
        }

        ret = mbedtls_md5_ret(buf, update_len, digest);
        BREAK_ON_FAILURE(ret);

        cpy_len = rm_len >= sizeof(digest) ? sizeof(digest) : rm_len;
        memcpy(pos, digest, cpy_len);

        rm_len -= cpy_len;
    }

    ret = 0;

BREAK_LABEL:

    if ( buf )
        mbedtls_free(buf);

    return ret;
}

/* Different from shadowsocks */
int gen_iv(const char *seed, unsigned char *iv, size_t iv_len) {
    int ret = -1;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    BREAK_ON_NULL(iv);
    BREAK_ON_NULL(iv_len);

    ret = mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func,
        &entropy,
        (const unsigned char*)seed,
        strlen(seed));
    BREAK_ON_FAILURE(ret);

    ret = mbedtls_ctr_drbg_random(
        &ctr_drbg,
        iv,
        iv_len);

BREAK_LABEL:

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

const CRYPTO_INFO *get_method_by_name(const char *name) {
    const CRYPTO_INFO *ret = NULL, *info;

    BREAK_ON_NULL(name);
    for ( unsigned int i = 0; i < Methods_Count; ++i ) {
        info = &Methods[i];

        if ( 0 == strcasecmp(name, info->ss_name) ) {
            ret = info;
            break;
        }
    }

BREAK_LABEL:

    return ret;
}

const CRYPTO_INFO *get_method_by_type(mbedtls_cipher_type_t type) {
    const CRYPTO_INFO *ret = NULL, *info;

    for ( unsigned int i = 0; i < Methods_Count; ++i ) {
        info = &Methods[i];

        if ( type == info->type ) {
            ret = info;
            break;
        }
    }

BREAK_LABEL:

    return ret;
}
