/**
 *  Copyright 2025, LeNidViolet.
 *  Created by LeNidViolet on 2025/7/27.
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
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

int     dns_cache_init(void);
void    dns_cache_clear(void);

struct sockaddr*    dns_cache_find_ip(const char *host, int req_ipv4);
const char*         dns_cache_find_host(const struct sockaddr *addr);
int                 dns_cache_add(const char *host, const struct sockaddr *addr);

int main() {
    union{
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } addr1;
    union{
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } addr2;
    struct sockaddr* addrp;
    int ret;
    char *host;


    dns_cache_init();
    dns_cache_init();


    // IPV4
    memset(&addr1, 0, sizeof(addr1));
    addr1.addr4.sin_family = AF_INET;
    addr1.addr4.sin_addr.s_addr = 0x01020304;

    ret = dns_cache_add("www.abc.com", &addr1.addr);
    assert(0 == ret);

    ret = dns_cache_add("www.abc.com", &addr1.addr);
    assert(0 == ret);

    ret = dns_cache_add("www.abc.com.cn", &addr1.addr);
    assert(0 == ret);

    addr1.addr4.sin_addr.s_addr = 0x01020305;

    ret = dns_cache_add("www.abc.com", &addr1.addr);
    assert(0 == ret);

    ret = dns_cache_add("www.abc.com.cn", &addr1.addr);
    assert(0 == ret);


    addrp = dns_cache_find_ip("www.abc.com", 1);
    assert(NULL != addrp);
    addrp = dns_cache_find_ip("www.abc.com", 0);
    assert(NULL == addrp);



    // IPV6
    memset(&addr2, 0, sizeof(addr2));
    addr2.addr6.sin6_family = AF_INET6;
    addr2.addr6.sin6_addr.__u6_addr.__u6_addr32[0] = 0xffffffff;
    addr2.addr6.sin6_addr.__u6_addr.__u6_addr32[1] = 0xeeeeeeee;
    addr2.addr6.sin6_addr.__u6_addr.__u6_addr32[2] = 0xdddddddd;
    addr2.addr6.sin6_addr.__u6_addr.__u6_addr32[3] = 0xcccccccc;

    ret = dns_cache_add("www.abc.com", &addr2.addr);
    assert(0 == ret);

    addrp = dns_cache_find_ip("www.abc.com", 1);
    assert(NULL != addrp);
    addrp = dns_cache_find_ip("www.abc.com", 0);
    assert(NULL != addrp);



    // FIND HOST
    host = (char*)dns_cache_find_host(&addr1.addr);
    assert(NULL != host);

    host = (char*)dns_cache_find_host(&addr2.addr);
    assert(NULL != host);

    addr1.addr4.sin_addr.s_addr = 0x01020304;
    host = (char*)dns_cache_find_host(&addr1.addr);
    assert(NULL != host);


    dns_cache_init();
    dns_cache_clear();
    dns_cache_clear();
}
