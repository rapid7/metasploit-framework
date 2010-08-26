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
#ifndef __ARM_MMAN_H__
#define __ARM_MMAN_H__

#include <asm-generic/mman.h>

#define MAP_GROWSDOWN 0x0100  
#define MAP_DENYWRITE 0x0800  
#define MAP_EXECUTABLE 0x1000  
#define MAP_LOCKED 0x2000  
#define MAP_NORESERVE 0x4000  
#define MAP_POPULATE 0x8000  
#define MAP_NONBLOCK 0x10000  

#define MCL_CURRENT 1  
#define MCL_FUTURE 2  

#endif
