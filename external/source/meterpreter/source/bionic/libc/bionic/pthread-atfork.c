/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/queue.h>

static pthread_mutex_t handler_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER;

struct atfork_t
{
    CIRCLEQ_ENTRY(atfork_t) entries;

    void (*prepare)(void);
    void (*child)(void);
    void (*parent)(void);
};
static CIRCLEQ_HEAD(atfork_head_t, atfork_t) atfork_head = \
    CIRCLEQ_HEAD_INITIALIZER(atfork_head);

void __bionic_atfork_run_prepare()
{
    struct atfork_t *cursor;

    /* We will lock this here, and unlock it in the parent and child functions.
     * This ensures that nobody can modify the handler array between the calls
     * to the prepare and parent/child handlers.
     *
     * TODO: If a handler mucks with the list, it could cause problems.  Right
     *       now it's ok because all they can do is add new items to the end
     *       of the list, but if/when we implement cleanup in dlclose() things
     *       will get more interesting...
     */
    pthread_mutex_lock(&handler_mutex);

    /* Call pthread_atfork() prepare handlers.  Posix states that the prepare
     * handlers should be called in the reverse order of the parent/child
     * handlers, so we iterate backwards.
     */
    for (cursor = atfork_head.cqh_last;
         cursor != (void*)&atfork_head;
         cursor = cursor->entries.cqe_prev) {
        if (cursor->prepare != NULL) {
            cursor->prepare();
        }
    }
}

void __bionic_atfork_run_child()
{
    struct atfork_t *cursor;

    /* Call pthread_atfork() child handlers */
    for (cursor = atfork_head.cqh_first;
         cursor != (void*)&atfork_head;
         cursor = cursor->entries.cqe_next) {
        if (cursor->child != NULL) {
            cursor->child();
        }
    }

    pthread_mutex_unlock(&handler_mutex);
}

void __bionic_atfork_run_parent()
{
    struct atfork_t *cursor;

    /* Call pthread_atfork() parent handlers */
    for (cursor = atfork_head.cqh_first;
         cursor != (void*)&atfork_head;
         cursor = cursor->entries.cqe_next) {
        if (cursor->parent != NULL) {
            cursor->parent();
        }
    }

    pthread_mutex_unlock(&handler_mutex);
}

int pthread_atfork(void (*prepare)(void), void (*parent)(void), void(*child)(void))
{
    struct atfork_t *entry = malloc(sizeof(struct atfork_t));

    if (entry == NULL) {
        return ENOMEM;
    }

    entry->prepare = prepare;
    entry->parent = parent;
    entry->child = child;

    pthread_mutex_lock(&handler_mutex);
    CIRCLEQ_INSERT_TAIL(&atfork_head, entry, entries);
    pthread_mutex_unlock(&handler_mutex);

    return 0;
}
