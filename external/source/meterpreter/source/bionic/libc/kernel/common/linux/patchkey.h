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
#ifndef _LINUX_PATCHKEY_H_INDIRECT
#error "patchkey.h included directly"
#endif

#ifndef _LINUX_PATCHKEY_H
#define _LINUX_PATCHKEY_H

#include <endian.h>

#ifdef __BYTE_ORDER
#if __BYTE_ORDER == __BIG_ENDIAN
#define _PATCHKEY(id) (0xfd00|id)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define _PATCHKEY(id) ((id<<8)|0x00fd)
#else
#error "could not determine byte order"
#endif
#endif

#endif
