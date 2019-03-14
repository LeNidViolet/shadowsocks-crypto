/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/7.
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
#ifndef SHADOWSOCKS_NETIO_DNSC_H
#define SHADOWSOCKS_NETIO_DNSC_H

#include <netinet/in.h>
#include "shadowsocks-crypto/list.h"

typedef struct {
    LIST_ENTRY list;

    char host[64];

    union{
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    }ipv4;
    int ipv4_valid;

    union{
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    }ipv6;
    int ipv6_valid;
} DNSC;

int dnsc_init(void);
DNSC *dnsc_find(const char *host);
DNSC *dnsc_find_ip(const struct sockaddr *addr_v4, const struct sockaddr *addr_v6);
DNSC *dnsc_add(const char *host, const struct sockaddr *addr_v4, const struct sockaddr *addr_v6);
void dnsc_remove(DNSC *dnsc);
void dnsc_clear(void);

#endif //SHADOWSOCKS_NETIO_DNSC_H
