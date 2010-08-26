/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was automatically generated from a Linux kernel header
 ***   of the same name, to make information necessary for userspace to
 ***   call into the kernel available to libc.  It contains only constants,
 ***   structures, and macros generated from the original header, and thus,
 ***   contains no copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/
#ifndef _LINUX_DIRENT_H
#define _LINUX_DIRENT_H

struct dirent {
 long d_ino;
 __kernel_off_t d_off;
 unsigned short d_reclen;
 char d_name[256];
};

struct dirent64 {
 __u64 d_ino;
 __s64 d_off;
 unsigned short d_reclen;
 unsigned char d_type;
 char d_name[256];
};

#endif
