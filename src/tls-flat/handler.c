/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/23.
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
#include <string.h>
#include <stdio.h>
#include <zconf.h>
#include "internal.h"

/* 消息向上传递 */
void tlsflat_notify(int level, const char *format, ...) {
    va_list ap;
    char msg[1024];

    va_start(ap, format);
    vsnprintf(msg, sizeof(msg), format, ap);
    va_end(ap);

    sscrypto_on_msg(level, msg);
}

/* 解密明文向上传递 */
void tlsflat_plain_stream(stream_session *ss, int direct, const char *data, size_t data_len) {
    sscrypto_tls_on_plain_stream(data, data_len, direct, ss->caller_ctx);
}

/* 对外接口, 应当在TLS连接创建完毕时调用 */
void tlsflat_on_stream_connection_made(const address_pair *addr, void *stream_id, void *caller_ctx, void **tls_ctx) {
    static unsigned int index = 0;
    stream_session *ss;
    const int init_size = 1024;

    ss = malloc(sizeof(*ss));
    memset(ss, 0, sizeof(*ss));
    ss->index = index++;
    ss->stream_id = stream_id;
    ss->caller_ctx = caller_ctx;
    ss->srv.ss = ss;
    ss->clt.ss = ss;
    ss->bytes_in = 0;
    ss->bytes_out = 0;

    ss->local = *addr->local;
    ss->remote = *addr->remote;

    buf_range_alloc(&ss->srv.buf_in, init_size);
    buf_range_alloc(&ss->clt.buf_in, init_size);
    buf_range_alloc(&ss->srv.buf_out, init_size);
    buf_range_alloc(&ss->clt.buf_out, init_size);

    ss->srv.is_local = 1;
    ss->clt.is_local = 0;

    ss->srv.tls_state = Tls_HandShaking;
    ss->clt.tls_state = Tls_HandShaking;

    ss->srv.wrstate = Write_Idel;
    ss->clt.wrstate = Write_Idel;

    mbedtls_ssl_init(&ss->srv.ssl);
    mbedtls_ssl_init(&ss->clt.ssl);

    tls_associate_context(&ss->srv.ssl, 1);
    tls_associate_context(&ss->clt.ssl, 0);

    mbedtls_ssl_set_bio(&ss->srv.ssl, &ss->srv, on_tls_send, on_tls_recv, NULL);
    mbedtls_ssl_set_bio(&ss->clt.ssl, &ss->clt, on_tls_send, on_tls_recv, NULL);

    *tls_ctx = ss;
}


/* 对外接口, 应当在TLS连接销毁时调用 */
void tlsflat_on_stream_teardown(void *tls_ctx) {
    stream_session *ss;

    if ( tls_ctx ) {
        ss = (stream_session *)tls_ctx;

        mbedtls_ssl_free(&ss->srv.ssl);
        mbedtls_ssl_free(&ss->clt.ssl);

        buf_range_free(&ss->srv.buf_in);
        buf_range_free(&ss->clt.buf_in);
        buf_range_free(&ss->srv.buf_out);
        buf_range_free(&ss->clt.buf_out);
        free(ss);
    }
}


/*
 * 对外接口, 应当在有数据来临时(原始未解密)调用
 * 因为TLS解密可能需要的数据量比一个TCP包中所含数据多得多,
 * 所以调用者应该根据此函数返回值执行对应操作.
 * 一般来说每个TCP包都需要丢弃掉.
 */
int tlsflat_on_plain_stream(const buf_range *buf, int direct, void *ctx) {
    stream_session *ss;
    tls_session *ts;
    size_t rm_len, total_len;
    buf_range *in;
    int action;

    ss = (stream_session*)ctx;

    if ( ss->closing ) {
        action = TERMINATE;
        BREAK_NOW;
    }

    ts = direct == STREAM_UP ? &ss->srv : &ss->clt;
    in = &ts->buf_in;

    if ( STREAM_UP == direct )
        ss->bytes_out += buf->data_len;
    else
        ss->bytes_in += buf->data_len;

    tlsflat_notify(DEBUG, "%4d [%s] ==> %d BYTES %s SIDE",
                   ss->index,
                   ss->sni_name[0] ? ss->sni_name : ss->remote.host,
                   (int)buf->data_len,
                   ts->is_local ? "SERVER" : "CLIENT");

    rm_len = in->buf_len - in->data_len;
    assert(rm_len >= 0);
    if ( rm_len >= buf->data_len ) {
        if ( in->buf_len - (in->data_base - in->buf_base + in->data_len) >= buf->data_len ) {
            memcpy(in->data_base + in->data_len, buf->data_base, buf->data_len);
        } else {
            memmove(in->buf_base, in->data_base, in->data_len);
            memcpy(in->buf_base + in->data_len, buf->data_base, buf->data_len);
            in->data_base = in->buf_base;
        }
        in->data_len += buf->data_len;

    } else {
        total_len = in->data_len + buf->data_len;
        buf_range_relloc(in, total_len);

        memcpy(in->data_base + in->data_len, buf->data_base, buf->data_len);
        in->data_len = total_len;
    }

    action = tls_recv_done_do_next(ts);

BREAK_LABEL:

    return action;
}
