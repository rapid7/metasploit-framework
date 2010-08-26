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
#ifndef _LINUX_MEMPOOL_H
#define _LINUX_MEMPOOL_H

#include <linux/wait.h>

struct kmem_cache;

typedef void * (mempool_alloc_t)(gfp_t gfp_mask, void *pool_data);
typedef void (mempool_free_t)(void *element, void *pool_data);

typedef struct mempool_s {
 spinlock_t lock;
 int min_nr;
 int curr_nr;
 void **elements;

 void *pool_data;
 mempool_alloc_t *alloc;
 mempool_free_t *free;
 wait_queue_head_t wait;
} mempool_t;

#endif
