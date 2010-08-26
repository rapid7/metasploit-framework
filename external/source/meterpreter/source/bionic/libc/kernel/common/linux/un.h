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
#ifndef _LINUX_UN_H
#define _LINUX_UN_H

#define UNIX_PATH_MAX 108

struct sockaddr_un {
 sa_family_t sun_family;
 char sun_path[UNIX_PATH_MAX];
};

#endif
