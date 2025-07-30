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
#include "dgramsc.h"

#ifdef _WIN32
#define strcasecmp _stricmp
#endif

static LIST_ENTRY ds_list;
static int ds_inited = 0;
static int ds_outstanding = 0;

static void dgrams_close(dgrams *ds);
static void dgrams_free(dgrams *ds);
static void dgrams_close_done(uv_handle_t *handle);

void dgrams_init(void) {
    if ( 0 == ds_inited ) {
        InitializeListHead(&ds_list);
        ds_inited = 1;
    }
}

dgrams *dgrams_add(const char *key, uv_loop_t *loop) {
    dgrams *ds;

    ENSURE((ds = malloc(sizeof(*ds))) != NULL);
    memset(ds, 0, sizeof(*ds));
    CHECK(0 == uv_udp_init(loop, &ds->udp_out));
    CHECK(0 == uv_timer_init(loop, &ds->timer));
    uv_handle_set_data((uv_handle_t*)&ds->udp_out, ds);
    uv_handle_set_data((uv_handle_t*)&ds->timer, ds);

    snprintf(ds->key, sizeof(ds->key), "%s", key);

    InsertTailList(&ds_list, &ds->list);

    ds->state = u_using;
    ds_outstanding++;
    return ds;
}

dgrams *dgrams_find_by_key(const char *key) {
    dgrams *ret = NULL, *ds;
    LIST_ENTRY *next;

    BREAK_ON_NULL(key);

    for ( next = ds_list.Blink; next != &ds_list ; next = next->Blink ) {
        ds = CONTAINER_OF(next, dgrams, list);

        if ( 0 == strcasecmp(key, ds->key) ) {
            ret = ds;
            break;
        }
    }

BREAK_LABEL:

    return ret;
}

void dgrams_remove(dgrams *ds) {
    if ( ds ) {
        RemoveEntryList(&ds->list);
        dgrams_close(ds);
    }
}

void dgrams_clear(void) {
    dgrams *ds;
    LIST_ENTRY *list;

    while ( !IsListEmpty(&ds_list) ) {
        list = RemoveHeadList(&ds_list);
        ds = CONTAINER_OF(list, dgrams, list);

        // dgrams_close(ds);
        // 我们目前使用uv walk遍历所有句柄进行关闭 这里就直接释放资源了
        dgrams_free(ds);
    }
}

static void dgrams_close(dgrams *ds) {
    if ( ds->state < u_closing1 ) {
        ds->state = u_closing1;

        if (!uv_is_closing((uv_handle_t *)&ds->udp_out)) {
            uv_close((uv_handle_t *)&ds->udp_out, dgrams_close_done);
        }
        if (!uv_is_closing((uv_handle_t *)&ds->timer)) {
            uv_timer_stop(&ds->timer);
            uv_close((uv_handle_t *)&ds->timer, dgrams_close_done);
        }
    }
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
static void dgrams_close_done(uv_handle_t *handle) {
    dgrams *ds;

    ds = uv_handle_get_data(handle);

    ds->state++;
    if ( u_dead == ds->state ) {
        dgrams_free(ds);
    }
}

static void dgrams_free(dgrams *ds) {
    if ( DEBUG_CHECKS )
        memset(ds, -1, sizeof(*ds));
    free(ds);

    ds_outstanding--;

    if ( 0 == ds_outstanding )
        ssnetio_on_msg(LOG_KEY, "dgrams outstanding return to 0");
}
