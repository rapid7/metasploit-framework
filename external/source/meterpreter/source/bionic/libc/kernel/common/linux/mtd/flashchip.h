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
#ifndef __MTD_FLASHCHIP_H__
#define __MTD_FLASHCHIP_H__

#include <linux/sched.h>

typedef enum {
 FL_READY,
 FL_STATUS,
 FL_CFI_QUERY,
 FL_JEDEC_QUERY,
 FL_ERASING,
 FL_ERASE_SUSPENDING,
 FL_ERASE_SUSPENDED,
 FL_WRITING,
 FL_WRITING_TO_BUFFER,
 FL_OTP_WRITE,
 FL_WRITE_SUSPENDING,
 FL_WRITE_SUSPENDED,
 FL_PM_SUSPENDED,
 FL_SYNCING,
 FL_UNLOADING,
 FL_LOCKING,
 FL_UNLOCKING,
 FL_POINT,
 FL_XIP_WHILE_ERASING,
 FL_XIP_WHILE_WRITING,
 FL_UNKNOWN
} flstate_t;

struct flchip {
 unsigned long start;

 int ref_point_counter;
 flstate_t state;
 flstate_t oldstate;

 unsigned int write_suspended:1;
 unsigned int erase_suspended:1;
 unsigned long in_progress_block_addr;

 spinlock_t *mutex;
 spinlock_t _spinlock;
 wait_queue_head_t wq;
 int word_write_time;
 int buffer_write_time;
 int erase_time;

 void *priv;
};

struct flchip_shared {
 spinlock_t lock;
 struct flchip *writing;
 struct flchip *erasing;
};

#endif
