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
#ifndef SHADOWSOCKS_NETIO_DNS_CACHE_H
#define SHADOWSOCKS_NETIO_DNS_CACHE_H

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif
#include "../comm/list.h"

struct dns_cache_ip;
typedef struct {
    struct dns_cache_ip *next;
    union{
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } addr;
} dns_cache_ip;

typedef struct {
    LIST_ENTRY list;

    char host[64];

    dns_cache_ip *ip;
} dns_cache_entry;


void    dns_cache_init(void);
void    dns_cache_clear(void);

/* 根据域名查询缓存IP */
struct sockaddr*    dns_cache_find_ip(const char *host, int req_ipv4);
/* 根据IP反查域名 */
const char*         dns_cache_find_host(const struct sockaddr *addr);
/* 添加新条目 */
int                 dns_cache_add(const char *host, const struct sockaddr *addr);

#endif //SHADOWSOCKS_NETIO_DNS_CACHE_H
