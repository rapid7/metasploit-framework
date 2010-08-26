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
#ifndef _ASM_GENERIC_MMAN_H
#define _ASM_GENERIC_MMAN_H

#define PROT_READ 0x1  
#define PROT_WRITE 0x2  
#define PROT_EXEC 0x4  
#define PROT_SEM 0x8  
#define PROT_NONE 0x0  
#define PROT_GROWSDOWN 0x01000000  
#define PROT_GROWSUP 0x02000000  

#define MAP_SHARED 0x01  
#define MAP_PRIVATE 0x02  
#define MAP_TYPE 0x0f  
#define MAP_FIXED 0x10  
#define MAP_ANONYMOUS 0x20  

#define MS_ASYNC 1  
#define MS_INVALIDATE 2  
#define MS_SYNC 4  

#define MADV_NORMAL 0  
#define MADV_RANDOM 1  
#define MADV_SEQUENTIAL 2  
#define MADV_WILLNEED 3  
#define MADV_DONTNEED 4  

#define MADV_REMOVE 9  
#define MADV_DONTFORK 10  
#define MADV_DOFORK 11  

#define MAP_ANON MAP_ANONYMOUS
#define MAP_FILE 0

#endif
