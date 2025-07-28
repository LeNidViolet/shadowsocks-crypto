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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#define strcasecmp _stricmp

#else
#include <netinet/in.h>
#endif

#include "shadowsocks-crypto/shadowsocks-crypto.h"
#include "internal.h"
#include "s5.h"

int sockaddr_to_str(const struct sockaddr *addr, ADDRESS *addr_s, int set_port) {
    const struct sockaddr_in6 *in6;
    const struct sockaddr_in *in;

    switch (addr->sa_family) {
    case AF_INET:
        in = (const struct sockaddr_in *)addr;
        CHECK(0 == uv_ip4_name(in, addr_s->ip, sizeof(addr_s->ip)));
        if ( set_port )
            addr_s->port = htons_u(in->sin_port);

        break;
    case AF_INET6:
        in6 = (const struct sockaddr_in6 *)&addr;
        CHECK(0 == uv_ip6_name(in6, addr_s->ip, sizeof(addr_s->ip)));
        if ( set_port )
            addr_s->port = htons_u(in6->sin6_port);

        break;
    default:
        UNREACHABLE();
    }

    return 0;
}

void sockaddr_cpy(const struct sockaddr *src, struct sockaddr *dst) {
    const struct sockaddr_in6 *in6;
    const struct sockaddr_in *in;

    switch (src->sa_family) {
    case AF_INET:
        in = (const struct sockaddr_in *)src;
        *(struct sockaddr_in *)dst = *in;
        break;

    case AF_INET6:
        in6 = (const struct sockaddr_in6 *)src;
        *(struct sockaddr_in6 *)dst = *in6;
        break;

    default:
        UNREACHABLE();
        break;
    }
}

int sockaddr_equal(const struct sockaddr *src, const struct sockaddr *dst, int cmp_port) {
    int ret = 0;
    const struct sockaddr_in6 *in6s;
    const struct sockaddr_in *ins;
    const struct sockaddr_in6 *in6d;
    const struct sockaddr_in *ind;

    if ( src->sa_family != dst->sa_family )
        BREAK_NOW;

    switch ( src->sa_family ) {
    case AF_INET:
        ins = (const struct sockaddr_in *)src;
        ind = (const struct sockaddr_in *)dst;
        if ( cmp_port ) {
            if ( ins->sin_port != ind->sin_port )
                BREAK_NOW;
        }

        if ( ins->sin_addr.s_addr != ind->sin_addr.s_addr )
            BREAK_NOW;
        break;

    case AF_INET6:
        in6s = (const struct sockaddr_in6 *)src;
        in6d = (const struct sockaddr_in6 *)dst;
        if ( cmp_port ) {
            if ( in6s->sin6_port != in6d->sin6_port )
                BREAK_NOW;
        }

        if ( 0 != memcmp(&in6s->sin6_addr, &in6d->sin6_addr, sizeof(in6s->sin6_addr)) )
            BREAK_NOW;
        break;

    default:
        UNREACHABLE();
        break;
    }

    ret = 1;
BREAK_LABEL:

    return ret;
}

void sockaddr_set_port(struct sockaddr *addr, unsigned short port) {
    struct sockaddr_in6 *in6;
    struct sockaddr_in *in;

    switch (addr->sa_family) {
    case AF_INET:
        in = (struct sockaddr_in *)addr;
        in->sin_port = htons_u(port);
        break;

    case AF_INET6:
        in6 = (struct sockaddr_in6 *)addr;
        in6->sin6_port = htons_u(port);
        break;

    default:
        UNREACHABLE();
        break;
    }
}

int str_tcp_endpoint(const uv_tcp_t *tcp_handle, ENDPOINT ep, ADDRESS *addr_s) {
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } s;
    int addr_len = sizeof(s);

    if ( ep == peer ) {
        CHECK(0 == uv_tcp_getpeername(tcp_handle,
                                      &s.addr,
                                      &addr_len));
    } else if ( ep == sock ) {
        CHECK(0 == uv_tcp_getsockname(tcp_handle,
                                      &s.addr,
                                      &addr_len));
    } else {
        UNREACHABLE();
    }

    return sockaddr_to_str(&s.addr, addr_s, 1);
}


int s5_simple_check(const char *data, size_t data_len) {
    int ret;
    const char *p;
    int nmethod, i, method;

    if ( data_len < 3 ) {
        ret = s5_invalid_length;
        BREAK_NOW;
    }

    p = data;
    if ( *p != '\5' ) {
        ret = s5_invalid_version;
        BREAK_NOW;
    }

    nmethod = (int)*++p;
    if ( data_len < 2 + nmethod ) {
        ret = s5_invalid_length;
        BREAK_NOW;
    }

    ret = s5_invalid_method;
    for ( i = 0; i < nmethod; i++ ) {
        method = (int)*++p;
        if ( 0 == method ) {
            ret = 0;
            break;
        }
    }

BREAK_LABEL:

    return ret;
}

int s5_parse_addr(BUF_RANGE *buf, ADDRESS *addr) {
    s5_ctx parser;
    uint8_t *p;
    size_t len;
    s5_err err;
    int offset, ret = -1;
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } s;

    p = (uint8_t *)buf->data_base;
    len = buf->data_len;
    err = s5_parse_ss(&parser, &p, &len);
    BREAK_ON_FALSE(err == s5_exec_cmd);

    offset = (int)((char*)p - buf->data_base);
    buf->data_base = buf->data_base + offset;
    buf->data_len = buf->data_len - offset;

    switch ( parser.atyp )
    {
    case s5_atyp_ipv4:
        s.addr4.sin_family = AF_INET;
        memcpy(&s.addr4.sin_addr, parser.daddr, sizeof(s.addr4.sin_addr));

        CHECK(0 == uv_ip4_name(&s.addr4, addr->domain, sizeof(addr->domain)));
        break;

    case s5_atyp_ipv6:
        s.addr6.sin6_family = AF_INET6;
        memcpy(&s.addr6.sin6_addr, parser.daddr, sizeof(s.addr6.sin6_addr));

        CHECK(0 == uv_ip6_name(&s.addr6, addr->domain, sizeof(addr->domain)));
        break;

    case s5_atyp_host:
        memcpy(addr->domain, parser.daddr, strlen((char*)parser.daddr));
        break;
    default:
        BREAK_NOW;
    }
    addr->port = parser.dport;

    ret = 0;

BREAK_LABEL:

    return ret;
}
