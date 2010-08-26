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

/* implement flockfile(), ftrylockfile() and funlockfile()
 *
 * we can't use the OpenBSD implementation which uses kernel-specific
 * APIs not available on Linux.
 *
 * Ideally, this would be trivially implemented by adding a
 * pthread_mutex_t field to struct __sFILE as defined in
 * <stdio.h>.
 *
 * However, since we don't want to bring pthread into the mix
 * as well as change the size of a public API/ABI structure,
 * we're going to store the data out-of-band.
 *
 * we use a hash-table to map FILE* pointers to recursive mutexes
 * fclose() will call __fremovelock() defined below to remove
 * a pointer from the table.
 *
 * the behaviour, if fclose() is called while the corresponding
 * file is locked is totally undefined.
 */
#include <stdio.h>
#include <pthread.h>
#include <string.h>

/* a node in the hash table */
typedef struct FileLock {
    struct FileLock*  next;
    FILE*             file;
    pthread_mutex_t   mutex;
} FileLock;

/* use a static hash table. We assume that we're not going to
 * lock a really large number of FILE* objects on an embedded
 * system.
 */
#define  FILE_LOCK_BUCKETS  32

typedef struct {
    pthread_mutex_t   lock;
    FileLock*         buckets[ FILE_LOCK_BUCKETS ];
} LockTable;

static LockTable*      _lockTable;
static pthread_once_t  _lockTable_once = PTHREAD_ONCE_INIT;

static void
lock_table_init( void )
{
    _lockTable = malloc(sizeof(*_lockTable));
    if (_lockTable != NULL) {
        pthread_mutex_init(&_lockTable->lock, NULL);
        memset(_lockTable->buckets, 0, sizeof(_lockTable->buckets));
    }
}

static LockTable*
lock_table_lock( void )
{
    pthread_once( &_lockTable_once, lock_table_init );
    pthread_mutex_lock( &_lockTable->lock );
    return _lockTable;
}

static void
lock_table_unlock( LockTable*  t )
{
    pthread_mutex_unlock( &t->lock );
}

static FileLock**
lock_table_lookup( LockTable*  t, FILE*  f )
{
    uint32_t    hash = (uint32_t)(void*)f;
    FileLock**  pnode;

    hash = (hash >> 2) ^ (hash << 17);
    pnode = &t->buckets[hash % FILE_LOCK_BUCKETS];
    for (;;) {
        FileLock*  node = *pnode;
        if (node == NULL || node->file == f)
            break;
        pnode = &node->next;
    }
    return pnode;
}

void
flockfile(FILE * fp)
{
    LockTable*  t = lock_table_lock();

    if (t != NULL) {
        FileLock**  lookup = lock_table_lookup(t, fp);
        FileLock*   lock   = *lookup;

        if (lock == NULL) {
            pthread_mutexattr_t  attr;

            /* create a new node in the hash table */
            lock = malloc(sizeof(*lock));
            if (lock == NULL) {
                lock_table_unlock(t);
                return;
            }
            lock->next        = NULL;
            lock->file        = fp;

            pthread_mutexattr_init(&attr);
            pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
            pthread_mutex_init( &lock->mutex, &attr );

            *lookup           = lock;
        }
        lock_table_unlock(t);

        /* we assume that another thread didn't destroy 'lock'
        * by calling fclose() on the FILE*. This can happen if
        * the client is *really* buggy, but we don't care about
        * such code here.
        */
        pthread_mutex_lock(&lock->mutex);
    }
}


int
ftrylockfile(FILE *fp)
{
    int         ret = -1;
    LockTable*  t   = lock_table_lock();

    if (t != NULL) {
        FileLock**  lookup = lock_table_lookup(t, fp);
        FileLock*   lock   = *lookup;

        lock_table_unlock(t);

        /* see above comment about why we assume that 'lock' can
        * be accessed from here
        */
        if (lock != NULL && !pthread_mutex_trylock(&lock->mutex)) {
            ret = 0;  /* signal success */
        }
    }
    return ret;
}

void
funlockfile(FILE * fp)
{
    LockTable*  t = lock_table_lock();

    if (t != NULL) {
        FileLock**  lookup = lock_table_lookup(t, fp);
        FileLock*   lock   = *lookup;

        if (lock != NULL)
            pthread_mutex_unlock(&lock->mutex);

        lock_table_unlock(t);
    }
}


/* called from fclose() to remove the file lock */
void
__fremovelock(FILE*  fp)
{
    LockTable*  t = lock_table_lock();

    if (t != NULL) {
        FileLock**  lookup = lock_table_lookup(t, fp);
        FileLock*   lock   = *lookup;

        if (lock != NULL) {
            *lookup   = lock->next;
            lock->file = NULL;
        }
        lock_table_unlock(t);
        free(lock);
    }
}
