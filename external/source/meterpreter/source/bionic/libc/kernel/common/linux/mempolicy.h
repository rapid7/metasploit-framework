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
#ifndef _LINUX_MEMPOLICY_H
#define _LINUX_MEMPOLICY_H 1

#include <linux/errno.h>

#define MPOL_DEFAULT 0
#define MPOL_PREFERRED 1
#define MPOL_BIND 2
#define MPOL_INTERLEAVE 3

#define MPOL_MAX MPOL_INTERLEAVE

#define MPOL_F_NODE (1<<0)  
#define MPOL_F_ADDR (1<<1)  

#define MPOL_MF_STRICT (1<<0)  
#define MPOL_MF_MOVE (1<<1)  
#define MPOL_MF_MOVE_ALL (1<<2)  
#define MPOL_MF_INTERNAL (1<<3)  

#endif
