/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/13.
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
#ifndef SHADOWSOCKS_CRYPTO_SHADOWSOCKS_CRYPTO_H
#define SHADOWSOCKS_CRYPTO_SHADOWSOCKS_CRYPTO_H

#include "shadowsocks-netio/shadowsocks-netio.h"

typedef struct SSCRYPTO_BASE_CONFIG{
    const char *bind_host;
    unsigned short bind_port;
    unsigned int idel_timeout;

    /* Client sode only. */
    const char *ss_srv_addr;
    unsigned short ss_srv_port;

    const char *password;
    const char *method;

    int as_server;  /* 0=client, server otherwise */
} SSCRYPTO_BASE_CONFIG;

typedef struct SSCRYPTO_CTX{
    SSCRYPTO_BASE_CONFIG config;
    SSNETIO_CALLBACKS callbacks;
} SSCRYPTO_CTX;

int sscrypto_launch(SSCRYPTO_CTX *ctx);

#endif //SHADOWSOCKS_CRYPTO_SHADOWSOCKS_CRYPTO_H
