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
#ifndef __LINUX_COMPLETION_H
#define __LINUX_COMPLETION_H

#include <linux/wait.h>

struct completion {
 unsigned int done;
 wait_queue_head_t wait;
};

#define COMPLETION_INITIALIZER(work)   { 0, __WAIT_QUEUE_HEAD_INITIALIZER((work).wait) }

#define COMPLETION_INITIALIZER_ONSTACK(work)   ({ init_completion(&work); work; })

#define DECLARE_COMPLETION(work)   struct completion work = COMPLETION_INITIALIZER(work)

#define DECLARE_COMPLETION_ONSTACK(work) DECLARE_COMPLETION(work)

#define INIT_COMPLETION(x) ((x).done = 0)

#endif
