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
#ifndef _ZCONF_H
#define _ZCONF_H

#ifndef MAX_MEM_LEVEL
#define MAX_MEM_LEVEL 8
#endif

#ifndef MAX_WBITS
#define MAX_WBITS 15  
#endif

#ifndef DEF_WBITS
#define DEF_WBITS MAX_WBITS
#endif

#if MAX_MEM_LEVEL >= 8
#define DEF_MEM_LEVEL 8
#else
#define DEF_MEM_LEVEL MAX_MEM_LEVEL
#endif

typedef unsigned char Byte;
typedef unsigned int uInt;
typedef unsigned long uLong;
typedef void *voidp;

#endif
