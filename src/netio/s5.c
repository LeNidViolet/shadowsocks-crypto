/* Copyright StrongLoop, Inc. All rights reserved.
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

#include "s5.h"
#include <errno.h>
#include <stdlib.h>  /* abort() */
#include <string.h>  /* memset() */

enum {
    s5_version,
    s5_nmethods,
    s5_methods,
    s5_auth_pw_version,
    s5_auth_pw_userlen,
    s5_auth_pw_username,
    s5_auth_pw_passlen,
    s5_auth_pw_password,
    s5_req_version,
    s5_req_cmd,
    s5_req_reserved,
    s5_req_atyp,
    s5_req_atyp_host,
    s5_req_daddr,
    s5_req_dport0,
    s5_req_dport1,
    s5_dead
};

s5_err s5_parse_ss(s5_ctx *cx, uint8_t **data, size_t *size) {
    /* atyp:1 daddr:4(ipv4) dport:2*/
    if ( *size < 7 )
        return s5_bad_prot;

    memset(cx, 0, sizeof(*cx));
    cx->state = s5_req_atyp;

    return s5_parse(cx, data, size);
}

s5_err s5_parse(s5_ctx *cx, uint8_t **data, size_t *size) {
    s5_err err;
    uint8_t *p;
    uint8_t c;
    size_t i;
    size_t n;

    p = *data;
    n = *size;
    i = 0;

    while (i < n) {
        c = p[i];
        i += 1;
        switch (cx->state) {
        case s5_version:
            if (c != 5) {
                err = s5_bad_version;
                goto out;
            }
            cx->state = s5_nmethods;
            break;

        case s5_nmethods:
            cx->arg0 = 0;
            cx->arg1 = c;  /* Number of bytes to read. */
            cx->state = s5_methods;
            break;

        case s5_methods:
            if (cx->arg0 < cx->arg1) {
                switch (c) {
                case 0:
                    cx->methods |= S5_AUTH_NONE;
                    break;
                case 1:
                    cx->methods |= S5_AUTH_GSSAPI;
                    break;
                case 2:
                    cx->methods |= S5_AUTH_PASSWD;
                    break;
                    /* Ignore everything we don't understand. */
                default:
                    break;
                }
                cx->arg0 += 1;
            }
            if (cx->arg0 == cx->arg1) {
                err = s5_auth_select;
                goto out;
            }
            break;

        case s5_auth_pw_version:
            if (c != 1) {
                err = s5_bad_version;
                goto out;
            }
            cx->state = s5_auth_pw_userlen;
            break;

        case s5_auth_pw_userlen:
            cx->arg0 = 0;
            cx->userlen = c;
            cx->state = s5_auth_pw_username;
            break;

        case s5_auth_pw_username:
            if (cx->arg0 < cx->userlen) {
                cx->username[cx->arg0] = c;
                cx->arg0 += 1;
            }
            if (cx->arg0 == cx->userlen) {
                cx->username[cx->userlen] = '\0';
                cx->state = s5_auth_pw_passlen;
            }
            break;

        case s5_auth_pw_passlen:
            cx->arg0 = 0;
            cx->passlen = c;
            cx->state = s5_auth_pw_password;
            break;

        case s5_auth_pw_password:
            if (cx->arg0 < cx->passlen) {
                cx->password[cx->arg0] = c;
                cx->arg0 += 1;
            }
            if (cx->arg0 == cx->passlen) {
                cx->password[cx->passlen] = '\0';
                cx->state = s5_req_version;
                err = s5_auth_verify;
                goto out;
            }
            break;

        case s5_req_version:
            if (c != 5) {
                err = s5_bad_version;
                goto out;
            }
            cx->state = s5_req_cmd;
            break;

        case s5_req_cmd:
            switch (c) {
            case 1:  /* TCP connect */
                cx->cmd = s5_cmd_tcp_connect;
                break;
            case 3:  /* UDP associate */
                cx->cmd = s5_cmd_udp_assoc;
                break;
            default:
                err = s5_bad_cmd;
                goto out;
            }
            cx->state = s5_req_reserved;
            break;

        case s5_req_reserved:
            cx->state = s5_req_atyp;
            break;

        case s5_req_atyp:
            cx->arg0 = 0;
            switch (c) {
            case 1:  /* IPv4, four octets. */
                cx->state = s5_req_daddr;
                cx->atyp = s5_atyp_ipv4;
                cx->arg1 = 4;
                break;
            case 3:  /* Hostname.  First byte is length. */
                cx->state = s5_req_atyp_host;
                cx->atyp = s5_atyp_host;
                cx->arg1 = 0;
                break;
            case 4:  /* IPv6, sixteen octets. */
                cx->state = s5_req_daddr;
                cx->atyp = s5_atyp_ipv6;
                cx->arg1 = 16;
                break;
            default:
                err = s5_bad_atyp;
                goto out;
            }
            break;

        case s5_req_atyp_host:
            cx->arg1 = c;
            cx->state = s5_req_daddr;
            break;

        case s5_req_daddr:
            if (cx->arg0 < cx->arg1) {
                cx->daddr[cx->arg0] = c;
                cx->arg0 += 1;
            }
            if (cx->arg0 == cx->arg1) {
                cx->daddr[cx->arg1] = '\0';
                cx->state = s5_req_dport0;
            }
            break;

        case s5_req_dport0:
            cx->dport = c << 8u;
            cx->state = s5_req_dport1;
            break;

        case s5_req_dport1:
            cx->dport |= c;
            cx->state = s5_dead;
            err = s5_exec_cmd;
            goto out;

        case s5_dead:
            break;

        default:
            abort();
        }
    }
    err = s5_ok;

out:
    *data = p + i;
    *size = n - i;
    return err;
}
