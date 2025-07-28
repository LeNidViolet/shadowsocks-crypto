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
#include <string.h>
#include "internal.h"
#include "../comm/list.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"


typedef struct {
    LIST_ENTRY list;

    mbedtls_x509_crt *crt;
    mbedtls_pk_context *pk;
} crt_node;

static LIST_ENTRY pool_list;
static int pool_inited = 0;
static int pool_ncrt = 0;

static int x509_cn_in_crt(
    const mbedtls_x509_crt *crt,
    const char *cn);
static int domain_in_crt_pool(const char *domain);



int crt_pool_init(void) {
    if ( 0 == pool_inited ) {
        InitializeListHead(&pool_list);

        pool_inited = 1;
    }

    return 0;
}

int crt_pool_get(
    const char *domain,
    mbedtls_x509_crt **crt,
    mbedtls_pk_context **pk) {

    crt_node *cn;
    int ret = -1;

    BREAK_ON_NULL(domain);

    for ( PLIST_ENTRY nextlist = pool_list.Flink; nextlist != &pool_list; nextlist = nextlist->Flink ) {
        cn = CONTAINER_OF(nextlist, crt_node, list);

        ret = x509_cn_in_crt(cn->crt, domain);
        if ( ret == 0 ) {
            *crt = cn->crt;
            *pk = cn->pk;
            break;
        }
    }

BREAK_LABEL:

    return ret;
}


// ReSharper disable once CppParameterMayBeConst
static int cn_memcasecmp(const void *s1, const void *s2, size_t len) {
    size_t i;
    unsigned char diff;
    const unsigned char *n1 = s1, *n2 = s2;

    for ( i = 0; i < len; i++ ) {
        diff = n1[i] ^ n2[i];

        if ( diff == 0 )
            continue;

        if ( diff == 32 &&
             ((n1[i] >= 'a' && n1[i] <= 'z') ||
              (n1[i] >= 'A' && n1[i] <= 'Z'))) {
            continue;
        }

        return (-1);
    }

    return (0);
}

static int cn_check_wildcard(const char *cn, const mbedtls_x509_buf *name) {
    size_t i;
    // ReSharper disable once CppLocalVariableMayBeConst
    size_t cn_idx = 0, cn_len = strlen(cn);

    /* We can't have a match if there is no wildcard to match */
    if ( name->len < 3 || name->p[0] != '*' || name->p[1] != '.' )
        return (-1);

    for ( i = 0; i < cn_len; ++i ) {
        if ( cn[i] == '.' ) {
            cn_idx = i;
            break;
        }
    }

    if ( cn_idx == 0 )
        return (-1);

    if ( cn_len - cn_idx == name->len - 1 &&
         cn_memcasecmp(name->p + 1, cn + cn_idx, name->len - 1) == 0 ) {
        return (0);
    }

    return (-1);
}


static int crt_check_cn(
    const mbedtls_x509_buf *name,
    // ReSharper disable once CppParameterMayBeConst
    const char *cn, size_t cn_len) {
    /* try exact match */
    if ( name->len == cn_len &&
         cn_memcasecmp(cn, name->p, cn_len) == 0 ) {
        return (0);
    }

    /* try wildcard match */
    if ( cn_check_wildcard(cn, name) == 0 ) {
        return (0);
    }

    return (-1);
}


/*
 * domain 是否存在于某个证书中
 * 存在返回 0
 */
static int x509_cn_in_crt(
    const mbedtls_x509_crt *crt,
    const char *cn) {
    int ret = -1;
    const mbedtls_x509_name *name;
    const mbedtls_x509_sequence *cur;
    const size_t cn_len = strlen(cn);

    if ( crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
        for ( cur = &crt->subject_alt_names; cur != NULL; cur = cur->next ) {
            if ( 0 == crt_check_cn(&cur->buf, cn, cn_len) ) {
                ret = 0;
                break;
            }
        }
    } else {
        /* 如果不包含 subject alt name. 则直接使用 subject 来判断 */
        for ( name = &crt->subject; name != NULL; name = name->next ) {
            if ( 0 == MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) &&
                 0 == crt_check_cn(&name->val, cn, cn_len) ) {
                ret = 0;
                break;
            }
        }
    }

    return ret;
}


int crt_pool_add(
    const char *domain,
    mbedtls_x509_crt *crt,
    mbedtls_pk_context *pk) {

    int ret = -1;
    crt_node *cn;
    size_t len;

    if ( 0 == domain_in_crt_pool(domain) ) {
        ret = 0;
        BREAK_NOW;
    }

    len = strlen(domain);
    BREAK_ON_FALSE(len > 0 && len < 128);

    cn = malloc(sizeof(*cn));
    BREAK_ON_NULL(cn);
    memset(cn, 0, sizeof(crt_node));

    cn->pk = pk;
    cn->crt = crt;

    InsertHeadList(&pool_list, &cn->list);
    ++pool_ncrt;

    tlsflat_on_msg(
        LOG_INFO,
        "CRT POOL ADD DOMAIN [%s] TOTAL[%d]",
        domain,
        pool_ncrt);

    ret = 0;

BREAK_LABEL:

    return ret;
}


/**
 * @brief                   证书池中是否存在指定域名的证书
 *
 * @param domain            域名
 *
 * @return                  存在返回0 否则非0
 */
static int domain_in_crt_pool(const char *domain) {
    int ret = -1;
    crt_node *cn;
    size_t len;
    char buf[128] = {0};

    len = strlen(domain);
    BREAK_ON_FALSE(len > 0 && len < sizeof(buf));
    memcpy(buf, domain, len);

    for ( PLIST_ENTRY nextlist = pool_list.Flink; nextlist != &pool_list; nextlist = nextlist->Flink ) {
        cn = CONTAINER_OF(nextlist, crt_node, list);

        ret = x509_cn_in_crt(cn->crt, buf);
        if ( 0 == ret )
            break;
    }

BREAK_LABEL:

    return ret;
}


void crt_pool_clear(void) {
    crt_node *cn;
    PLIST_ENTRY list;

    while (!IsListEmpty(&pool_list)) {
        list = RemoveHeadList(&pool_list);
        cn = CONTAINER_OF(list, crt_node, list);

        cn->pk = NULL;
        mbedtls_x509_crt_free(cn->crt);
        free(cn->crt);
        cn->crt = NULL;
        free(cn);

        pool_ncrt--;
    }

    ASSERT(0 == pool_ncrt);
}
