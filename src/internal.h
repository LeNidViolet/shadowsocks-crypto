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
#include "shadowsocks-netio/shadowsocks-netio.h"
#include "mbedtls/cipher.h"

#define DEFAULT_METHOD          "AES-256-CFB"
#define DEFAULT_PASSWORD        "7Ykd3@!kfl0&"

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

    SSNETIO_CALLBACKS ori_cbs; /* caller's callback */
}CRYPTO_ENV;

#define BREAK_LABEL                                     \
    cleanup

#define BREAK_ON_FAILURE_WITH_LABEL(_status, label)     \
if ( (_status) != 0 )                                   \
    goto label

#define BREAK_ON_FAILURE(_status)                       \
    BREAK_ON_FAILURE_WITH_LABEL(_status, BREAK_LABEL)

#define BREAK_ON_NULL_WITH_LABEL(value, label)          \
if ( !(value) )                                         \
    goto label

#define BREAK_ON_NULL(_value)                           \
    BREAK_ON_NULL_WITH_LABEL(_value, BREAK_LABEL)

#define BREAK_ON_FALSE        BREAK_ON_NULL

#define BREAK_NOW                                       \
    goto BREAK_LABEL

#if defined(NDEBUG)
# define ASSERT(exp)
# define CHECK(exp)     do { if (!(exp)) abort(); } while (0)
# define DEBUG_CHECKS (0)
#else
# define ASSERT(exp)  assert(exp)
# define CHECK(exp)   assert(exp)
# define DEBUG_CHECKS (1)
#endif

#define ENSURE(exp)     do { if (!(exp)) abort(); } while (0)

#define UNREACHABLE()   CHECK(!"Unreachable code reached.")


/* UTIL.C */
/* return 0 if success */
int gen_iv(const char *seed, unsigned char *iv, size_t iv_len);
/* return 0 if success */
int gen_key(const char *seed, unsigned char *key, size_t key_len);

const CRYPTO_INFO *get_method_by_name(const char *name);
const CRYPTO_INFO *get_method_by_type(mbedtls_cipher_type_t type);


/* CALLBACK.C */
int init_calback_unit(void);
void free_callback_unit(void);
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
