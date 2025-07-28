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
#include <stdlib.h>
#include "dns_cache.h"
#include "internal.h"

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

static LIST_ENTRY cache_list;
static int entry_outstanding = 0;
static int ip_outstanding = 0;
static int cache_inited = 0;

static void dns_cache_free(dns_cache_entry *dnsc);

/* TODO: ADD DNS TIMEOUT */
// 非线程安全 未加锁

void dns_cache_init(void) {
    if ( 0 == cache_inited ) {
        InitializeListHead(&cache_list);
        cache_inited = 1;
    }
}

// ReSharper disable once CppParameterMayBeConst
struct sockaddr* dns_cache_find_ip(const char *host, int req_ipv4) {
    struct sockaddr *ret = NULL;
    dns_cache_entry *dnsc;
    LIST_ENTRY *next;

    BREAK_ON_NULL(host);

    for ( next = cache_list.Blink; next != &cache_list; next = next->Blink ) {
        dnsc = CONTAINER_OF(next, dns_cache_entry, list);

        if ( 0 == strcasecmp(host, dnsc->host) ) {

            for ( dns_cache_ip *ip = dnsc->ip; NULL != ip ; ip = (dns_cache_ip*)ip->next ) {
                if ( req_ipv4 && AF_INET == ip->addr.addr.sa_family ) {
                    ret = &ip->addr.addr;
                    break;
                }
                if ( !req_ipv4 && AF_INET6 == ip->addr.addr.sa_family ) {
                    ret = &ip->addr.addr;
                    break;
                }
            }
            break;
        }
    }

BREAK_LABEL:

    return ret;
}

const char* dns_cache_find_host(const struct sockaddr *addr) {
    const char *ret = NULL;
    dns_cache_entry *dnsc;
    int equal;

    for ( LIST_ENTRY *next = cache_list.Blink; next != &cache_list ; next = next->Blink ) {
        dnsc = CONTAINER_OF(next, dns_cache_entry, list);

        for (const dns_cache_ip *ip = dnsc->ip; NULL != ip ; ip = (dns_cache_ip*)ip->next ) {
            if ( addr->sa_family == ip->addr.addr.sa_family ) {
                equal = sockaddr_equal(addr, &ip->addr.addr, 0);
                if ( equal ) {
                    ret = dnsc->host;
                    break;
                }
            }
        }
        if ( ret )
            break;
    }

BREAK_LABEL:

    return ret;
}

static dns_cache_entry* dns_cache_host_capture(const char *host) {
    dns_cache_entry *ret = NULL;
    dns_cache_entry *dnsc;
    LIST_ENTRY *next;

    BREAK_ON_NULL(host);

    for ( next = cache_list.Blink; next != &cache_list; next = next->Blink ) {
        dnsc = CONTAINER_OF(next, dns_cache_entry, list);

        if ( 0 == strcasecmp(host, dnsc->host) ) {
            ret = dnsc;
            break;
        }
    }

BREAK_LABEL:

    return ret;
}

static dns_cache_ip* dns_cache_ip_capture(dns_cache_entry *dnsc, const struct sockaddr *addr) {
    dns_cache_ip* ret = NULL;
    int equal;

    for ( dns_cache_ip *ip = dnsc->ip; NULL != ip; ip = (dns_cache_ip*)ip->next ) {
        if ( addr->sa_family == ip->addr.addr.sa_family ) {
            equal = sockaddr_equal(addr, &ip->addr.addr, 0);
            if ( equal ) {
                ret = ip;
                break;
            }
        }
    }

    return ret;
}

int dns_cache_add(const char *host, const struct sockaddr *addr) {
    int ret = -1;
    dns_cache_entry *dnsc;
    dns_cache_ip *ip = NULL;

    BREAK_ON_NULL(host);

    dnsc = dns_cache_host_capture(host);
    if ( dnsc ) {
        ip = dns_cache_ip_capture(dnsc, addr);
        if ( ip ) {
            // already exists
            ret = 0;
            BREAK_NOW;
        }
    } else {
        ENSURE((dnsc = malloc(sizeof(*dnsc))) != NULL);
        memset(dnsc, 0, sizeof(*dnsc));

        snprintf(dnsc->host, sizeof(dnsc->host), "%s", host);

        InsertTailList(&cache_list, &dnsc->list);
        entry_outstanding++;
    }

    ENSURE((ip = malloc(sizeof(*ip))) != NULL);
    memset(ip, 0, sizeof(*ip));

    sockaddr_cpy(addr, &ip->addr.addr);

    ip->next = (struct dns_cache_ip*)dnsc->ip;
    dnsc->ip = ip;

    ip_outstanding++;

    ret = 0;
BREAK_LABEL:

    return ret;
}


void dns_cache_clear(void) {
    dns_cache_entry *dnsc;
    LIST_ENTRY *list;

    while ( !IsListEmpty(&cache_list) ) {
        list = RemoveHeadList(&cache_list);
        dnsc = CONTAINER_OF(list, dns_cache_entry, list);

        dns_cache_free(dnsc);
    }

    CHECK(0 == entry_outstanding);
    CHECK(0 == ip_outstanding);
}

static void dns_cache_free(dns_cache_entry *dnsc) {
    dns_cache_ip *prev;

    for ( dns_cache_ip *ip = dnsc->ip; NULL != ip; ) {
        prev = ip;
        ip = (dns_cache_ip *)ip->next;

        if ( DEBUG_CHECKS )
            memset(prev, -1, sizeof(*prev));
        free(prev);

        ip_outstanding--;
    }

    if ( DEBUG_CHECKS )
        memset(dnsc, -1, sizeof(*dnsc));
    free(dnsc);

    entry_outstanding--;

    if ( 0 == entry_outstanding )
        ssnetio_on_msg(LOG_INFO, "dns cache entry outstanding return to 0");
    if ( 0 == ip_outstanding )
        ssnetio_on_msg(LOG_INFO, "dns cache ip outstanding return to 0");
}
