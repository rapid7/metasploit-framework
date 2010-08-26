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
#ifndef _LINUX_FUTEX_H
#define _LINUX_FUTEX_H

#include <linux/sched.h>

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_FD 2
#define FUTEX_REQUEUE 3
#define FUTEX_CMP_REQUEUE 4
#define FUTEX_WAKE_OP 5
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8

struct robust_list {
 struct robust_list __user *next;
};

struct robust_list_head {

 struct robust_list list;

 long futex_offset;

 struct robust_list __user *list_op_pending;
};

#define FUTEX_WAITERS 0x80000000

#define FUTEX_OWNER_DIED 0x40000000

#define FUTEX_TID_MASK 0x3fffffff

#define ROBUST_LIST_LIMIT 2048

#define FUTEX_OP_SET 0  
#define FUTEX_OP_ADD 1  
#define FUTEX_OP_OR 2  
#define FUTEX_OP_ANDN 3  
#define FUTEX_OP_XOR 4  
#define FUTEX_OP_OPARG_SHIFT 8  
#define FUTEX_OP_CMP_EQ 0  
#define FUTEX_OP_CMP_NE 1  
#define FUTEX_OP_CMP_LT 2  
#define FUTEX_OP_CMP_LE 3  
#define FUTEX_OP_CMP_GT 4  
#define FUTEX_OP_CMP_GE 5  
#define FUTEX_OP(op, oparg, cmp, cmparg)   (((op & 0xf) << 28) | ((cmp & 0xf) << 24)   | ((oparg & 0xfff) << 12) | (cmparg & 0xfff))
#endif
