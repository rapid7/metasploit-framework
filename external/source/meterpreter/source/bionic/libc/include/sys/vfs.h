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
#ifndef _SYS_VFS_H_
#define _SYS_VFS_H_

#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS

/* note: this corresponds to the kernel's statfs64 type */
struct statfs {
    uint32_t        f_type;
    uint32_t        f_bsize;
    uint64_t        f_blocks;
    uint64_t        f_bfree;
    uint64_t        f_bavail;
    uint64_t        f_files;
    uint64_t        f_ffree;
    __kernel_fsid_t f_fsid;
    uint32_t        f_namelen;
    uint32_t        f_frsize;
    uint32_t        f_spare[5];
};

#define  ADFS_SUPER_MAGIC      0xadf5
#define  AFFS_SUPER_MAGIC      0xADFF
#define  BEFS_SUPER_MAGIC      0x42465331
#define  BFS_MAGIC             0x1BADFACE
#define  CIFS_MAGIC_NUMBER     0xFF534D42
#define  CODA_SUPER_MAGIC      0x73757245
#define  COH_SUPER_MAGIC       0x012FF7B7
#define  CRAMFS_MAGIC          0x28cd3d45
#define  DEVFS_SUPER_MAGIC     0x1373
#define  EFS_SUPER_MAGIC       0x00414A53
#define  EXT_SUPER_MAGIC       0x137D
#define  EXT2_OLD_SUPER_MAGIC  0xEF51
#define  EXT2_SUPER_MAGIC      0xEF53
#define  EXT3_SUPER_MAGIC      0xEF53
#define  HFS_SUPER_MAGIC       0x4244
#define  HPFS_SUPER_MAGIC      0xF995E849
#define  HUGETLBFS_MAGIC       0x958458f6
#define  ISOFS_SUPER_MAGIC     0x9660
#define  JFFS2_SUPER_MAGIC     0x72b6
#define  JFS_SUPER_MAGIC       0x3153464a
#define  MINIX_SUPER_MAGIC     0x137F /* orig. minix */
#define  MINIX_SUPER_MAGIC2    0x138F /* 30 char minix */
#define  MINIX2_SUPER_MAGIC    0x2468 /* minix V2 */
#define  MINIX2_SUPER_MAGIC2   0x2478 /* minix V2, 30 char names */
#define  MSDOS_SUPER_MAGIC     0x4d44
#define  NCP_SUPER_MAGIC       0x564c
#define  NFS_SUPER_MAGIC       0x6969
#define  NTFS_SB_MAGIC         0x5346544e
#define  OPENPROM_SUPER_MAGIC  0x9fa1
#define  PROC_SUPER_MAGIC      0x9fa0
#define  QNX4_SUPER_MAGIC      0x002f
#define  REISERFS_SUPER_MAGIC  0x52654973
#define  ROMFS_MAGIC           0x7275
#define  SMB_SUPER_MAGIC       0x517B
#define  SYSV2_SUPER_MAGIC     0x012FF7B6
#define  SYSV4_SUPER_MAGIC     0x012FF7B5
#define  TMPFS_MAGIC           0x01021994
#define  UDF_SUPER_MAGIC       0x15013346
#define  UFS_MAGIC             0x00011954
#define  USBDEVICE_SUPER_MAGIC 0x9fa2
#define  VXFS_SUPER_MAGIC      0xa501FCF5
#define  XENIX_SUPER_MAGIC     0x012FF7B4
#define  XFS_SUPER_MAGIC       0x58465342
#define  _XIAFS_SUPER_MAGIC    0x012FD16D

extern int statfs(const char *, struct statfs *);
extern int fstatfs(int, struct statfs *);

__END_DECLS

#endif /* _SYS_VFS_H_ */
