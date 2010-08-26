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
#ifndef _LINUX_UTSNAME_H
#define _LINUX_UTSNAME_H

#define __OLD_UTS_LEN 8

struct oldold_utsname {
 char sysname[9];
 char nodename[9];
 char release[9];
 char version[9];
 char machine[9];
};

#define __NEW_UTS_LEN 64

struct old_utsname {
 char sysname[65];
 char nodename[65];
 char release[65];
 char version[65];
 char machine[65];
};

struct new_utsname {
 char sysname[65];
 char nodename[65];
 char release[65];
 char version[65];
 char machine[65];
 char domainname[65];
};

#endif
