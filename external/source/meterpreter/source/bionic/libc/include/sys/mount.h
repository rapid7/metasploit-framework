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
#ifndef _SYS_MOUNT_H
#define _SYS_MOUNT_H

#include <sys/cdefs.h>
#include <sys/ioctl.h>

__BEGIN_DECLS

/*
 * These are the fs-independent mount-flags: up to 32 flags are supported
 */
#define MS_RDONLY        1      /* Mount read-only */
#define MS_NOSUID        2      /* Ignore suid and sgid bits */
#define MS_NODEV         4      /* Disallow access to device special files */
#define MS_NOEXEC        8      /* Disallow program execution */
#define MS_SYNCHRONOUS  16      /* Writes are synced at once */
#define MS_REMOUNT      32      /* Alter flags of a mounted FS */
#define MS_MANDLOCK     64      /* Allow mandatory locks on an FS */
#define MS_DIRSYNC      128     /* Directory modifications are synchronous */
#define MS_NOATIME      1024    /* Do not update access times. */
#define MS_NODIRATIME   2048    /* Do not update directory access times */
#define MS_BIND         4096
#define MS_MOVE         8192
#define MS_REC          16384
#define MS_VERBOSE      32768
#define MS_POSIXACL     (1<<16) /* VFS does not apply the umask */
#define MS_ONE_SECOND   (1<<17) /* fs has 1 sec a/m/ctime resolution */
#define MS_ACTIVE       (1<<30)
#define MS_NOUSER       (1<<31)

/*
 * Superblock flags that can be altered by MS_REMOUNT
 */
#define MS_RMT_MASK     (MS_RDONLY|MS_SYNCHRONOUS|MS_MANDLOCK|MS_NOATIME|MS_NODIRATIME)

/*
 * Old magic mount flag and mask
 */
#define MS_MGC_VAL 0xC0ED0000
#define MS_MGC_MSK 0xffff0000

/*
 * umount2() flags
 */
#define MNT_FORCE	1	/* Forcibly unmount */
#define MNT_DETACH	2	/* Detach from tree only */
#define MNT_EXPIRE	4	/* Mark for expiry */

/*
 * Block device ioctls
 */
#define BLKROSET   _IO(0x12, 93) /* Set device read-only (0 = read-write).  */
#define BLKROGET   _IO(0x12, 94) /* Get read-only status (0 = read_write).  */
#define BLKRRPART  _IO(0x12, 95) /* Re-read partition table.  */
#define BLKGETSIZE _IO(0x12, 96) /* Return device size.  */
#define BLKFLSBUF  _IO(0x12, 97) /* Flush buffer cache.  */
#define BLKRASET   _IO(0x12, 98) /* Set read ahead for block device.  */
#define BLKRAGET   _IO(0x12, 99) /* Get current read ahead setting.  */

/*
 * Prototypes
 */
extern int mount(const char *, const char *,
		   const char *, unsigned long,
		   const void *);
extern int umount(const char *);
extern int umount2(const char *, int);
extern int pivot_root(const char *, const char *);

__END_DECLS

#endif /* _SYS_MOUNT_H */
