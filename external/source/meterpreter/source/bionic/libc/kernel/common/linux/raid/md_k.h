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
#ifndef _MD_K_H
#define _MD_K_H

#include "../../../drivers/md/dm-bio-list.h"

#define LEVEL_MULTIPATH (-4)
#define LEVEL_LINEAR (-1)
#define LEVEL_FAULTY (-5)

#define LEVEL_NONE (-1000000)

#define MaxSector (~(sector_t)0)
#define MD_THREAD_NAME_MAX 14

typedef struct mddev_s mddev_t;
typedef struct mdk_rdev_s mdk_rdev_t;

#define MAX_MD_DEVS 256  

#define MAX_CHUNK_SIZE (1<<30)

struct mdk_rdev_s
{
 struct list_head same_set;

 sector_t size;
 mddev_t *mddev;
 unsigned long last_events;

 struct block_device *bdev;

 struct page *sb_page;
 int sb_loaded;
 __u64 sb_events;
 sector_t data_offset;
 sector_t sb_offset;
 int sb_size;
 int preferred_minor;

 struct kobject kobj;

 unsigned long flags;
#define Faulty 1  
#define In_sync 2  
#define WriteMostly 4  
#define BarriersNotsupp 5  

 int desc_nr;
 int raid_disk;
 int saved_raid_disk;
 sector_t recovery_offset;

 atomic_t nr_pending;
 atomic_t read_errors;
 atomic_t corrected_errors;
};

struct mddev_s
{
 void *private;
 struct mdk_personality *pers;
 dev_t unit;
 int md_minor;
 struct list_head disks;
 int sb_dirty;
 int ro;

 struct gendisk *gendisk;

 struct kobject kobj;

 int major_version,
 minor_version,
 patch_version;
 int persistent;
 int chunk_size;
 time_t ctime, utime;
 int level, layout;
 char clevel[16];
 int raid_disks;
 int max_disks;
 sector_t size;
 sector_t array_size;
 __u64 events;

 char uuid[16];

 sector_t reshape_position;
 int delta_disks, new_level, new_layout, new_chunk;

 struct mdk_thread_s *thread;
 struct mdk_thread_s *sync_thread;
 sector_t curr_resync;
 unsigned long resync_mark;
 sector_t resync_mark_cnt;
 sector_t curr_mark_cnt;

 sector_t resync_max_sectors;

 sector_t resync_mismatches;

 sector_t suspend_lo;
 sector_t suspend_hi;

 int sync_speed_min;
 int sync_speed_max;

 int ok_start_degraded;

#define MD_RECOVERY_RUNNING 0
#define MD_RECOVERY_SYNC 1
#define MD_RECOVERY_ERR 2
#define MD_RECOVERY_INTR 3
#define MD_RECOVERY_DONE 4
#define MD_RECOVERY_NEEDED 5
#define MD_RECOVERY_REQUESTED 6
#define MD_RECOVERY_CHECK 7
#define MD_RECOVERY_RESHAPE 8
#define MD_RECOVERY_FROZEN 9

 unsigned long recovery;

 int in_sync;
 struct mutex reconfig_mutex;
 atomic_t active;

 int changed;
 int degraded;
 int barriers_work;
 struct bio *biolist;

 atomic_t recovery_active;
 wait_queue_head_t recovery_wait;
 sector_t recovery_cp;

 spinlock_t write_lock;
 wait_queue_head_t sb_wait;
 atomic_t pending_writes;

 unsigned int safemode;
 unsigned int safemode_delay;
 struct timer_list safemode_timer;
 atomic_t writes_pending;
 request_queue_t *queue;

 atomic_t write_behind;
 unsigned int max_write_behind;

 struct bitmap *bitmap;
 struct file *bitmap_file;
 long bitmap_offset;
 long default_bitmap_offset;

 struct list_head all_mddevs;
};

struct md_sysfs_entry {
 struct attribute attr;
 ssize_t (*show)(mddev_t *, char *);
 ssize_t (*store)(mddev_t *, const char *, size_t);
};

#define ITERATE_RDEV_GENERIC(head,rdev,tmp)     for ((tmp) = (head).next;   (rdev) = (list_entry((tmp), mdk_rdev_t, same_set)),   (tmp) = (tmp)->next, (tmp)->prev != &(head)   ; )
#define ITERATE_RDEV(mddev,rdev,tmp)   ITERATE_RDEV_GENERIC((mddev)->disks,rdev,tmp)
#define ITERATE_RDEV_PENDING(rdev,tmp)   ITERATE_RDEV_GENERIC(pending_raid_disks,rdev,tmp)

#define THREAD_WAKEUP 0

#define __wait_event_lock_irq(wq, condition, lock, cmd)  do {   wait_queue_t __wait;   init_waitqueue_entry(&__wait, current);     add_wait_queue(&wq, &__wait);   for (;;) {   set_current_state(TASK_UNINTERRUPTIBLE);   if (condition)   break;   spin_unlock_irq(&lock);   cmd;   schedule();   spin_lock_irq(&lock);   }   current->state = TASK_RUNNING;   remove_wait_queue(&wq, &__wait);  } while (0)

#define wait_event_lock_irq(wq, condition, lock, cmd)  do {   if (condition)   break;   __wait_event_lock_irq(wq, condition, lock, cmd);  } while (0)

#endif
