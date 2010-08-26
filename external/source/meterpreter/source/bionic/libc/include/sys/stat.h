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
#ifndef _SYS_STAT_H_
#define _SYS_STAT_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/time.h>
#include <linux/stat.h>

#include <endian.h>

__BEGIN_DECLS

/* really matches stat64 in the kernel, hence the padding
 * Note: The kernel zero's the padded region because glibc might read them
 * in the hope that the kernel has stretched to using larger sizes.
 */
struct stat {
    unsigned long long  st_dev;
    unsigned char       __pad0[4];

    unsigned long       __st_ino;
    unsigned int        st_mode;
    unsigned int        st_nlink;

    unsigned long       st_uid;
    unsigned long       st_gid;

    unsigned long long  st_rdev;
    unsigned char       __pad3[4];

    long long           st_size;
    unsigned long	st_blksize;
    unsigned long long  st_blocks;

    unsigned long       st_atime;
    unsigned long       st_atime_nsec;

    unsigned long       st_mtime;
    unsigned long       st_mtime_nsec;

    unsigned long       st_ctime;
    unsigned long       st_ctime_nsec;

    unsigned long long  st_ino;
};

/* For compatibility with GLibc, we provide macro aliases
 * for the non-Posix nano-seconds accessors.
 */
#define  st_atimensec  st_atime_nsec
#define  st_mtimensec  st_mtime_nsec
#define  st_ctimensec  st_ctime_nsec

extern int    chmod(const char *, mode_t);
extern int    fchmod(int, mode_t);
extern int    mkdir(const char *, mode_t);

extern int    stat(const char *, struct stat *);
extern int    fstat(int, struct stat *);
extern int    lstat(const char *, struct stat *);
extern int    mknod(const char *, mode_t, dev_t);
extern mode_t umask(mode_t);

#define  stat64    stat
#define  fstat64   fstat
#define  lstat64   lstat

static __inline__ int mkfifo(const char *__p, mode_t __m)
{
  return mknod(__p, (__m & ~S_IFMT) | S_IFIFO, (dev_t)0);
}

extern int  fstatat(int dirfd, const char *path, struct stat *buf, int flags);
extern int  mkdirat(int dirfd, const char *pathname, mode_t mode);
extern int fchownat(int dirfd, const char *path, uid_t owner, gid_t group, int flags);
extern int fchmodat(int dirfd, const char *path, mode_t mode, int flags);
extern int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);

__END_DECLS

#endif /* _SYS_STAT_H_ */
