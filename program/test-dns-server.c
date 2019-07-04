/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2019-07-03.
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
#include <stdio.h>
#include <string.h>
#include "uv.h"

int server_dns_launch(uv_loop_t *loop, const struct sockaddr *addr);


int main() {
    uv_loop_t *loop;
    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } addr;

    loop = uv_default_loop();
    uv_ip4_addr("0.0.0.0", 53, &addr.addr4);

    server_dns_launch(loop, &addr.addr);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
}


