/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/6.
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

static LIST_ENTRY dgrams_list;
static int dgrams_outstanding = 0;

static void dgrams_close(DGRAMS *dgrams);
static void dgrams_free(DGRAMS *dgrams);
static void dgrams_close_done(uv_handle_t *handle);

int dgrams_init(void) {
    InitializeListHead(&dgrams_list);

    return 0;
}

DGRAMS *dgrams_add(const char *key, uv_loop_t *loop) {
    DGRAMS *dgrams;

    ENSURE((dgrams = malloc(sizeof(*dgrams))) != NULL);
    memset(dgrams, 0, sizeof(*dgrams));
    CHECK(0 == uv_udp_init(loop, &dgrams->udp_out));
    CHECK(0 == uv_timer_init(loop, &dgrams->timer));
    uv_handle_set_data((uv_handle_t*)&dgrams->udp_out, dgrams);
    uv_handle_set_data((uv_handle_t*)&dgrams->timer, dgrams);

    snprintf(dgrams->key, sizeof(dgrams->key), "%s", key);

    InsertTailList(&dgrams_list, &dgrams->list);

    dgrams->state = u_using;
    dgrams_outstanding++;
    return dgrams;
}

DGRAMS *dgrams_find_by_key(const char *key) {
    DGRAMS *ret = NULL, *dgrams;
    LIST_ENTRY *next;

    BREAK_ON_NULL(key);

    for ( next = dgrams_list.Blink; next != &dgrams_list ; next = next->Blink ) {
        dgrams = CONTAINER_OF(next, DGRAMS, list);

        if ( 0 == strcasecmp(key, dgrams->key) ) {
            ret = dgrams;
            break;
        }
    }

BREAK_LABEL:

    return ret;
}

void dgrams_remove(DGRAMS *dgrams) {
    if ( dgrams ) {
        RemoveEntryList(&dgrams->list);
        dgrams_close(dgrams);
    }
}

void dgrams_clear(void) {
    DGRAMS *dgrams;
    LIST_ENTRY *list;

    while ( !IsListEmpty(&dgrams_list) ) {
        list = RemoveHeadList(&dgrams_list);
        dgrams = CONTAINER_OF(list, DGRAMS, list);

        dgrams_close(dgrams);
    }
}

static void dgrams_close(DGRAMS *dgrams) {
    if ( dgrams->state < u_closing ) {
        dgrams->state = u_closing;
        uv_close((uv_handle_t *)&dgrams->udp_out, dgrams_close_done);
        uv_close((uv_handle_t *)&dgrams->timer, dgrams_close_done);
    }
}

static void dgrams_close_done(uv_handle_t *handle) {
    DGRAMS *dgrams;

    dgrams = uv_handle_get_data(handle);

    dgrams->state++;
    if ( u_dead == dgrams->state ) {
        dgrams_free(dgrams);
    }
}

static void dgrams_free(DGRAMS *dgrams) {
    if ( DEBUG_CHECKS )
        memset(dgrams, -1, sizeof(*dgrams));
    free(dgrams);

    dgrams_outstanding--;
}
