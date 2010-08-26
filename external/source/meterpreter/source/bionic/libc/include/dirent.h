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
#ifndef _DIRENT_H_
#define _DIRENT_H_

#include <stdint.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

#ifndef DT_UNKNOWN
#define  DT_UNKNOWN     0
#define  DT_FIFO        1
#define  DT_CHR         2
#define  DT_DIR         4
#define  DT_BLK         6
#define  DT_REG         8
#define  DT_LNK         10
#define  DT_SOCK        12
#define  DT_WHT         14
#endif

/* the following structure is really called dirent64 by the kernel
 * headers. They also define a struct dirent, but the latter lack
 * the d_type field which is required by some libraries (e.g. hotplug)
 * who assume to be able to access it directly. sad...
 */
struct dirent {
    uint64_t         d_ino;
    int64_t          d_off;
    unsigned short   d_reclen;
    unsigned char    d_type;
    char             d_name[256];
};

typedef struct DIR  DIR;

extern  int              getdents(unsigned int, struct dirent*, unsigned int);
extern  DIR*             opendir(const char*  dirpath);
extern  DIR*             fdopendir(int fd);
extern  struct dirent*   readdir(DIR*  dirp);
extern  int              readdir_r(DIR*  dirp, struct dirent *entry, struct dirent **result);
extern  int              closedir(DIR*  dirp);
extern  void             rewinddir(DIR *dirp);
extern  int              dirfd(DIR* dirp);
extern  int              alphasort(const void *a, const void *b);
extern  int              scandir(const char *dir, struct dirent ***namelist,
                                 int(*filter)(const struct dirent *),
                                 int(*compar)(const struct dirent **, 
                                              const struct dirent **));

__END_DECLS

#endif /* _DIRENT_H_ */
