/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/20.
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
#ifndef TLS_FLAT_TLS_FLAT_H
#define TLS_FLAT_TLS_FLAT_H

#include <stddef.h>
#include "shadowsocks-crypto/shadowsocks-crypto.h"

int tlsflat_init(IOCTL_PORT *port);
void tlsflat_clear(void);

void tlsflat_on_stream_connection_made(ADDRESS_PAIR *addr, void *stream_id, void *caller_ctx, void **tls_ctx);
void tlsflat_on_stream_teardown(void *tls_ctx);
int tlsflat_on_plain_stream(MEM_RANGE *buf, int direct, void *ctx);

#endif //TLS_FLAT_TLS_FLAT_H
