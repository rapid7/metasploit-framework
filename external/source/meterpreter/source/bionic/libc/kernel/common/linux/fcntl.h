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
#ifndef _LINUX_FCNTL_H
#define _LINUX_FCNTL_H

#include <asm/fcntl.h>

#define F_SETLEASE (F_LINUX_SPECIFIC_BASE+0)
#define F_GETLEASE (F_LINUX_SPECIFIC_BASE+1)

#define F_NOTIFY (F_LINUX_SPECIFIC_BASE+2)

#define DN_ACCESS 0x00000001  
#define DN_MODIFY 0x00000002  
#define DN_CREATE 0x00000004  
#define DN_DELETE 0x00000008  
#define DN_RENAME 0x00000010  
#define DN_ATTRIB 0x00000020  
#define DN_MULTISHOT 0x80000000  

#define AT_FDCWD -100  
#define AT_SYMLINK_NOFOLLOW 0x100  
#define AT_REMOVEDIR 0x200  
#define AT_SYMLINK_FOLLOW 0x400  

#endif
