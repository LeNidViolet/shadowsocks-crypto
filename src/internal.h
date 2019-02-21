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
#ifndef SHADOWSOCKS_CRYPTO_INTERNAL_H
#define SHADOWSOCKS_CRYPTO_INTERNAL_H

#include <assert.h>
#include "shadowsocks-crypto/shadowsocks-crypto.h"
#include "shadowsocks-crypto/comm.h"
#include "mbedtls/cipher.h"

typedef struct {
    const mbedtls_cipher_type_t type;
    const char *mbedtls_name;
    const char *ss_name;
    const unsigned int key_len;
    const unsigned int iv_len;
}CRYPTO_INFO;


#define MAX_CRYPTO_KEY_LEN          (32)
#define MAX_CRYPTO_SALT_LEN         MAX_SS_SALT_LEN
typedef struct {
    const CRYPTO_INFO *method;
    unsigned char key[MAX_CRYPTO_KEY_LEN];

    SSCRYPTO_CALLBACKS callbacks;
}CRYPTO_ENV;

/* UTIL.C */
/* return 0 if success */
int gen_iv(const char *seed, unsigned char *iv, size_t iv_len);
/* return 0 if success */
int gen_key(const char *seed, unsigned char *key, size_t key_len);

const CRYPTO_INFO *get_method_by_name(const char *name);
const CRYPTO_INFO *get_method_by_type(mbedtls_cipher_type_t type);


/* CALLBACK.C */
int init_crypt_unit(void);
void free_crypt_unit(void);
void sscrypto_on_msg(int level, const char *msg);
void sscrypto_on_bind(const char *host, unsigned short port);
void sscrypto_on_stream_connection_made(ADDRESS_PAIR *addr, void *ctx);
void sscrypto_on_new_stream(ADDRESS *addr, void **ctx, void *stream_id);
void sscrypto_on_stream_teardown(void *ctx);
void sscrypto_on_new_dgram(ADDRESS_PAIR *addr, void **ctx);
void sscrypto_on_dgram_teardown(void *ctx);
int sscrypto_on_plain_stream(MEM_RANGE *buf, int direct, void *ctx);
void sscrypto_on_plain_dgram(MEM_RANGE *buf, int direct, void *ctx);
int sscrypto_on_stream_encrypt(MEM_RANGE *buf, void *ctx);
int sscrypto_on_stream_decrypt(MEM_RANGE *buf, void *ctx);
int sscrypto_on_dgram_encrypt(MEM_RANGE *buf);
int sscrypto_on_dgram_decrypt(MEM_RANGE *buf);

extern CRYPTO_ENV CryptoEnv;
#endif //SHADOWSOCKS_CRYPTO_INTERNAL_H
