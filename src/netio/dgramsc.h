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
#ifndef SHADOWSOCKS_NETIO_DGRAMSC_H
#define SHADOWSOCKS_NETIO_DGRAMSC_H

#include "uv.h"
#include "../comm/list.h"
#include "internal.h"


enum{
    u_using,
    u_closing1,
    u_closing2,
    u_dead
};

typedef struct {
    LIST_ENTRY list;

    int state;

    char key[128];

    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } local;

    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } remote;

    ADDRESS local_peer;
    ADDRESS remote_peer;

    uv_udp_send_t req_s;
    uv_udp_send_t req_c;
    uv_getaddrinfo_t req_dns;

    uv_udp_t *udp_in;
    uv_udp_t udp_out;
    uv_timer_t timer;

    char slab[MAX_SS_UDP_FRAME_LEN]; /* for recv */
    BUF_RANGE ss_buf;

    void *ctx;
} dgrams;

void dgrams_init(void);
dgrams *dgrams_add(const char *key, uv_loop_t *loop);
dgrams *dgrams_find_by_key(const char *key);
void dgrams_remove(dgrams *ds);
void dgrams_clear(void);

#endif //SHADOWSOCKS_NETIO_DGRAMSC_H
