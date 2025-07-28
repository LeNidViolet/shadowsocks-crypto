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

// ReSharper disable once CppParameterMayBeConst
void buf_range_alloc(BUF_RANGE *mr, size_t size) {
    mr->buf_base = mr->data_base = malloc(size);
    ASSERT(mr->buf_base);
    mr->buf_len = size;
    mr->data_len = 0;
}

void buf_range_free(BUF_RANGE *mr) {
    if ( mr->buf_base ) {
        free(mr->buf_base);
    }
    mr->buf_base = mr->data_base = NULL;
    mr->buf_len = mr->data_len = 0;
}

// ReSharper disable once CppParameterMayBeConst
void buf_range_relloc(BUF_RANGE *mr, size_t size) {
    char *tmp;

    if ( !mr->buf_base ) {
        buf_range_alloc(mr, size);
    } else if ( mr->buf_len < size ) {
        tmp = malloc(size);
        ASSERT(tmp);

        if ( mr->data_base && mr->data_len ) {
            memcpy(tmp, mr->data_base, mr->data_len);
        }
        free(mr->buf_base);
        mr->buf_base = mr->data_base = tmp;
        mr->buf_len = size;
        /* No change for buf->data_len */
    }
}
