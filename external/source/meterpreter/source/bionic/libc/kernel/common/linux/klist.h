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
#ifndef _LINUX_KLIST_H
#define _LINUX_KLIST_H

#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/kref.h>
#include <linux/list.h>

struct klist_node;
struct klist {
 spinlock_t k_lock;
 struct list_head k_list;
 void (*get)(struct klist_node *);
 void (*put)(struct klist_node *);
};

struct klist_node {
 struct klist * n_klist;
 struct list_head n_node;
 struct kref n_ref;
 struct completion n_removed;
};

struct klist_iter {
 struct klist * i_klist;
 struct list_head * i_head;
 struct klist_node * i_cur;
};

#endif
