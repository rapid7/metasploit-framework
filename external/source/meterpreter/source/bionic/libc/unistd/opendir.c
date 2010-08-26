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
#include <unistd.h>
#include <dirent.h>
#include <memory.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

struct DIR
{
    int              _DIR_fd;
    size_t           _DIR_avail;
    struct dirent*   _DIR_next;
    pthread_mutex_t  _DIR_lock;
    struct dirent    _DIR_buff[15];
};

int dirfd(DIR* dirp)
{
    return dirp->_DIR_fd;
}

DIR*  opendir( const char*  dirpath )
{
    DIR*  dir = malloc(sizeof(DIR));

    if (!dir)
        goto Exit;

    dir->_DIR_fd = open(dirpath, O_RDONLY|O_DIRECTORY);
    if (dir->_DIR_fd < 0)
    {
        free(dir);
        dir = NULL;
    }
    else
    {
        dir->_DIR_avail = 0;
        dir->_DIR_next  = NULL;
        pthread_mutex_init( &dir->_DIR_lock, NULL );
    }
Exit:
    return dir;
}


DIR*  fdopendir(int fd)
{
    DIR*  dir = malloc(sizeof(DIR));

    if (!dir)
        return 0;

    dir->_DIR_fd = fd;
    dir->_DIR_avail = 0;
    dir->_DIR_next  = NULL;
    pthread_mutex_init( &dir->_DIR_lock, NULL );

    return dir;
}


static struct dirent*
_readdir_unlocked(DIR*  dir)
{
    struct dirent*  entry;

    if ( !dir->_DIR_avail )
    {
        int  rc;

        for (;;) {
            rc = getdents( dir->_DIR_fd, dir->_DIR_buff, sizeof(dir->_DIR_buff));
            if (rc >= 0 || errno != EINTR)
            break;
        }
        if (rc <= 0)
            return NULL;

        dir->_DIR_avail = rc;
        dir->_DIR_next  = dir->_DIR_buff;
    }

    entry = dir->_DIR_next;

    /* perform some sanity checks here */
    if (((long)(void*)entry & 3) != 0)
        return NULL;

    if ( (unsigned)entry->d_reclen > sizeof(*entry)         ||
         entry->d_reclen <= offsetof(struct dirent, d_name) )
        goto Bad;

    if ( (char*)entry + entry->d_reclen > (char*)dir->_DIR_buff + sizeof(dir->_DIR_buff) )
        goto Bad;

    if ( !memchr( entry->d_name, 0, entry->d_reclen - offsetof(struct dirent, d_name)) )
        goto Bad; 

    dir->_DIR_next   = (struct dirent*)((char*)entry + entry->d_reclen);
    dir->_DIR_avail -= entry->d_reclen;

    return entry;

  Bad:
    errno = EINVAL;
    return NULL;
}


struct dirent*
readdir(DIR * dir)
{
    struct dirent *entry = NULL;

    pthread_mutex_lock( &dir->_DIR_lock );
    entry = _readdir_unlocked(dir);
    pthread_mutex_unlock( &dir->_DIR_lock );

    return entry;
}


int readdir_r(DIR*  dir, struct dirent *entry, struct dirent **result)
{
    struct dirent*  ent;
    int  save_errno = errno;
    int  retval;

    *result = NULL;
    errno   = 0;

    pthread_mutex_lock( &dir->_DIR_lock );

    ent    = _readdir_unlocked(dir);
    retval = errno;
    if (ent == NULL) {
        if (!retval) {
            errno = save_errno;
        }
    } else {
        if (!retval) {
            errno   = save_errno;
            *result = entry;
            memcpy( entry, ent, ent->d_reclen );
        }
    }

    pthread_mutex_unlock( &dir->_DIR_lock );

    return retval;
}



int closedir(DIR *dir)
{
  int rc;

  rc = close(dir->_DIR_fd);
  dir->_DIR_fd = -1;

  pthread_mutex_destroy( &dir->_DIR_lock );

  free(dir);
  return rc;
}


void   rewinddir(DIR *dir)
{
    pthread_mutex_lock( &dir->_DIR_lock );
    lseek( dir->_DIR_fd, 0, SEEK_SET );
    dir->_DIR_avail = 0;
    pthread_mutex_unlock( &dir->_DIR_lock );
}


int alphasort(const void *a, const void *b)
{
        struct dirent **d1, **d2;

        d1 = (struct dirent **) a;
        d2 = (struct dirent **) b;
        return strcmp((*d1)->d_name, (*d2)->d_name);
}


int scandir(const char *dir, struct dirent ***namelist,
            int(*filter)(const struct dirent *),
            int(*compar)(const struct dirent **, const struct dirent **))
{
    DIR *d;
    int n_elem = 0;
    struct dirent *this_de, *de;
    struct dirent **de_list = NULL;
    int de_list_size = 0;

    d = opendir(dir);
    if (d == NULL) {
        return -1;
    }

    while ((this_de = readdir(d)) != NULL) {
        if (filter && (*filter)(this_de) == 0) {
            continue;
        }
        if (n_elem == 0) {
            de_list_size = 4;
            de_list = (struct dirent **) 
                    malloc(sizeof(struct dirent *)*de_list_size);
            if (de_list == NULL) {
                return -1;
            }
        }
        else if (n_elem == de_list_size) {
            struct dirent **de_list_new;

            de_list_size += 10;
            de_list_new = (struct dirent **) 
                    realloc(de_list, sizeof(struct dirent *)*de_list_size);
            if (de_list_new == NULL) {
                free(de_list);
                return -1;
            }
            de_list = de_list_new;
        }
        de = (struct dirent *) malloc(sizeof(struct dirent));
        *de = *this_de;
        de_list[n_elem++] = de;
    }
    closedir(d);
    if (n_elem && compar) {
        qsort(de_list, n_elem, sizeof(struct dirent *), 
              (int (*)(const void *, const void *)) compar);
    }
    *namelist = de_list;
    return n_elem;
}
