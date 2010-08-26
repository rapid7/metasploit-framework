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
#include <pathconf.h>
#include <sys/vfs.h>
#include <sys/limits.h>
#include <linux/ext2_fs.h>
#include <linux/ext3_fs.h>
#include <errno.h>

/* these may not be defined yet by our headers */
#ifndef _POSIX_VDISABLE
#define _POSIX_VDISABLE  -1
#endif

#ifndef _POSIX_SYNC_IO
#define _POSIX_SYNC_IO  -1
#endif

#ifndef _POSIX_PRIO_IO
#define _POSIX_PRIO_IO  -1
#endif

#ifndef _POSIX_ASYNC_IO
#define _POSIX_ASYNC_IO  -1
#endif


static long
__filesizebits( struct statfs*  s )
{
#define   EOL_MAGIC   0x0000U

    /* list of known 64-bit aware filesystems */
    static const uint32_t  known64[] = {
        EXT2_SUPER_MAGIC,
        UFS_MAGIC,
        REISERFS_SUPER_MAGIC,
        XFS_SUPER_MAGIC,
        SMB_SUPER_MAGIC,
        UDF_SUPER_MAGIC,
        JFS_SUPER_MAGIC,
        NTFS_SB_MAGIC,
        VXFS_SUPER_MAGIC,
        EOL_MAGIC
    };
    int  nn = 0;

    for (;;) {
        if ( known64[nn] == EOL_MAGIC )
            return 32;

        if ( known64[nn] == s->f_type )
            return 64;
    }
}


static long
__link_max( struct statfs*  s )
{
   /* constant values were taken from official kernel headers.
    * I don't think this justified bringing in <linux/minix_fs.h> et al
    * into our cleaned-up kernel three
    */
    static const struct { uint32_t  type; int  max; }  knownMax[] =
    {
        { EXT2_SUPER_MAGIC, EXT2_LINK_MAX },
        { EXT3_SUPER_MAGIC, EXT3_LINK_MAX },
        { MINIX_SUPER_MAGIC, 250 },
        { MINIX2_SUPER_MAGIC, 65530 },
        { REISERFS_SUPER_MAGIC, 0xffff - 1000 },
        { UFS_MAGIC, 32000 },
        { EOL_MAGIC, 0 }
    };
    int   nn = 0;

    for (;;) {
        if ( knownMax[nn].type == EOL_MAGIC )
            return LINK_MAX;

        if ( knownMax[nn].type == s->f_type )
            return knownMax[nn].max;
    }
    return LINK_MAX;
}

static long
__2_symlinks( struct statfs*  s )
{
    /* list of know filesystems that don't support symlinks */
    static const uint32_t  knownNoSymlinks[] = {
        ADFS_SUPER_MAGIC, BFS_MAGIC, CRAMFS_MAGIC,
        EFS_SUPER_MAGIC, MSDOS_SUPER_MAGIC, NTFS_SB_MAGIC,
        QNX4_SUPER_MAGIC,
        EOL_MAGIC
    };
    int  nn = 0;

    for (;;) {
        if (knownNoSymlinks[nn] == 0)
            return 1;
        if (knownNoSymlinks[nn] == s->f_type)
            return 0;
    }
}

static long
__name_max( struct statfs*  s )
{
    return s->f_namelen;
}

long
pathconf(const char *path, int name)
{
    struct statfs  buf;
    int            ret = statfs( path, &buf );

    if (ret < 0)
        return -1;

    switch (name) {
    case _PC_FILESIZEBITS:
        return __filesizebits(&buf);

    case _PC_LINK_MAX:
        return __link_max(&buf);

    case _PC_MAX_CANON:
        return MAX_CANON;

    case _PC_MAX_INPUT:
        return MAX_INPUT;

    case _PC_NAME_MAX:
        return __name_max(&buf);

    case _PC_PATH_MAX:
        return PATH_MAX;

    case _PC_PIPE_BUF:
        return PIPE_BUF;

    case _PC_2_SYMLINKS:
        return __2_symlinks(&buf);

#if 0  /* don't know what to do there, the specs are really weird */
    case _PC_ALLOC_SIZE_MIN:
    case _PC_REC_INCR_XFER_SIZE:
    case _PC_REC_MAX_XFER_SIZE:
    case _PC_REC_MIN_XFER_SIZE:
    case _PC_REC_XFER_ALIGN:
#endif

    case _PC_SYMLINK_MAX:
        return -1;  /* no limit */

    case _PC_CHOWN_RESTRICTED:
        return _POSIX_CHOWN_RESTRICTED;

    case _PC_NO_TRUNC:
        return _POSIX_NO_TRUNC;

    case _PC_VDISABLE:
        return _POSIX_VDISABLE;

    case _PC_ASYNC_IO:
        return _POSIX_ASYNC_IO;

    case _PC_PRIO_IO:
        return _POSIX_PRIO_IO;

    case _PC_SYNC_IO:
        return _POSIX_SYNC_IO;

    default:
        errno = EINVAL;
        return -1;
    }
}

long fpathconf(int fildes, int name)
{
    struct statfs  buf;
    int            ret = fstatfs(fildes, &buf);

    if (ret < 0)
        return -1;

    switch (name) {
    case _PC_FILESIZEBITS:
        return __filesizebits(&buf);

    case _PC_LINK_MAX:
        return __link_max(&buf);

    case _PC_MAX_CANON:
        return MAX_CANON;

    case _PC_MAX_INPUT:
        return MAX_INPUT;

    case _PC_NAME_MAX:
        return __name_max(&buf);

    case _PC_PATH_MAX:
        return PATH_MAX;

    case _PC_PIPE_BUF:
        return PIPE_BUF;

    case _PC_2_SYMLINKS:
        return __2_symlinks(&buf);

#if 0  /* don't know what to do there, the specs are really weird */
    case _PC_ALLOC_SIZE_MIN:
    case _PC_REC_INCR_XFER_SIZE:
    case _PC_REC_MAX_XFER_SIZE:
    case _PC_REC_MIN_XFER_SIZE:
    case _PC_REC_XFER_ALIGN:
#endif

    case _PC_SYMLINK_MAX:
        return -1;  /* no limit */

    case _PC_CHOWN_RESTRICTED:
        return _POSIX_CHOWN_RESTRICTED;

    case _PC_NO_TRUNC:
        return _POSIX_NO_TRUNC;

    case _PC_VDISABLE:
        return _POSIX_VDISABLE;

    case _PC_ASYNC_IO:
        return _POSIX_ASYNC_IO;

    case _PC_PRIO_IO:
        return _POSIX_PRIO_IO;

    case _PC_SYNC_IO:
        return _POSIX_SYNC_IO;

    default:
        errno = EINVAL;
        return -1;
    }
}
