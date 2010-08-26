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
#ifndef _LINUX_BLKDEV_H
#define _LINUX_BLKDEV_H

#include <linux/major.h>
#include <linux/genhd.h>
#include <linux/list.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/pagemap.h>
#include <linux/backing-dev.h>
#include <linux/wait.h>
#include <linux/mempool.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/stringify.h>

#include <asm/scatterlist.h>

struct scsi_ioctl_command;

struct request_queue;
typedef struct request_queue request_queue_t;
struct elevator_queue;
typedef struct elevator_queue elevator_t;
struct request_pm_state;
struct blk_trace;

#define BLKDEV_MIN_RQ 4
#define BLKDEV_MAX_RQ 128  

struct as_io_context {
 spinlock_t lock;

 void (*dtor)(struct as_io_context *aic);
 void (*exit)(struct as_io_context *aic);

 unsigned long state;
 atomic_t nr_queued;
 atomic_t nr_dispatched;

 unsigned long last_end_request;
 unsigned long ttime_total;
 unsigned long ttime_samples;
 unsigned long ttime_mean;

 unsigned int seek_samples;
 sector_t last_request_pos;
 u64 seek_total;
 sector_t seek_mean;
};

struct cfq_queue;
struct cfq_io_context {
 struct rb_node rb_node;
 void *key;

 struct cfq_queue *cfqq[2];

 struct io_context *ioc;

 unsigned long last_end_request;
 sector_t last_request_pos;
 unsigned long last_queue;

 unsigned long ttime_total;
 unsigned long ttime_samples;
 unsigned long ttime_mean;

 unsigned int seek_samples;
 u64 seek_total;
 sector_t seek_mean;

 struct list_head queue_list;

 void (*dtor)(struct io_context *);
 void (*exit)(struct io_context *);
};

struct io_context {
 atomic_t refcount;
 struct task_struct *task;

 int (*set_ioprio)(struct io_context *, unsigned int);

 unsigned long last_waited;
 int nr_batch_requests;

 struct as_io_context *aic;
 struct rb_root cic_root;
};

struct io_context *current_io_context(gfp_t gfp_flags);
struct io_context *get_io_context(gfp_t gfp_flags);

struct request;
typedef void (rq_end_io_fn)(struct request *, int);

struct request_list {
 int count[2];
 int starved[2];
 int elvpriv;
 mempool_t *rq_pool;
 wait_queue_head_t wait[2];
};

#define BLK_MAX_CDB 16

struct request {
 struct list_head queuelist;
 struct list_head donelist;

 unsigned long flags;

 sector_t sector;
 unsigned long nr_sectors;

 unsigned int current_nr_sectors;

 sector_t hard_sector;
 unsigned long hard_nr_sectors;

 unsigned int hard_cur_sectors;

 struct bio *bio;
 struct bio *biotail;

 void *elevator_private;
 void *completion_data;

 int rq_status;
 int errors;
 struct gendisk *rq_disk;
 unsigned long start_time;

 unsigned short nr_phys_segments;

 unsigned short nr_hw_segments;

 unsigned short ioprio;

 int tag;

 int ref_count;
 request_queue_t *q;
 struct request_list *rl;

 struct completion *waiting;
 void *special;
 char *buffer;

 unsigned int cmd_len;
 unsigned char cmd[BLK_MAX_CDB];

 unsigned int data_len;
 unsigned int sense_len;
 void *data;
 void *sense;

 unsigned int timeout;
 int retries;

 rq_end_io_fn *end_io;
 void *end_io_data;
};

enum rq_flag_bits {
 __REQ_RW,
 __REQ_FAILFAST,
 __REQ_SORTED,
 __REQ_SOFTBARRIER,
 __REQ_HARDBARRIER,
 __REQ_FUA,
 __REQ_CMD,
 __REQ_NOMERGE,
 __REQ_STARTED,
 __REQ_DONTPREP,
 __REQ_QUEUED,
 __REQ_ELVPRIV,

 __REQ_PC,
 __REQ_BLOCK_PC,
 __REQ_SENSE,

 __REQ_FAILED,
 __REQ_QUIET,
 __REQ_SPECIAL,
 __REQ_DRIVE_CMD,
 __REQ_DRIVE_TASK,
 __REQ_DRIVE_TASKFILE,
 __REQ_PREEMPT,
 __REQ_PM_SUSPEND,
 __REQ_PM_RESUME,
 __REQ_PM_SHUTDOWN,
 __REQ_ORDERED_COLOR,
 __REQ_RW_SYNC,
 __REQ_NR_BITS,
};

#define REQ_RW (1 << __REQ_RW)
#define REQ_FAILFAST (1 << __REQ_FAILFAST)
#define REQ_SORTED (1 << __REQ_SORTED)
#define REQ_SOFTBARRIER (1 << __REQ_SOFTBARRIER)
#define REQ_HARDBARRIER (1 << __REQ_HARDBARRIER)
#define REQ_FUA (1 << __REQ_FUA)
#define REQ_CMD (1 << __REQ_CMD)
#define REQ_NOMERGE (1 << __REQ_NOMERGE)
#define REQ_STARTED (1 << __REQ_STARTED)
#define REQ_DONTPREP (1 << __REQ_DONTPREP)
#define REQ_QUEUED (1 << __REQ_QUEUED)
#define REQ_ELVPRIV (1 << __REQ_ELVPRIV)
#define REQ_PC (1 << __REQ_PC)
#define REQ_BLOCK_PC (1 << __REQ_BLOCK_PC)
#define REQ_SENSE (1 << __REQ_SENSE)
#define REQ_FAILED (1 << __REQ_FAILED)
#define REQ_QUIET (1 << __REQ_QUIET)
#define REQ_SPECIAL (1 << __REQ_SPECIAL)
#define REQ_DRIVE_CMD (1 << __REQ_DRIVE_CMD)
#define REQ_DRIVE_TASK (1 << __REQ_DRIVE_TASK)
#define REQ_DRIVE_TASKFILE (1 << __REQ_DRIVE_TASKFILE)
#define REQ_PREEMPT (1 << __REQ_PREEMPT)
#define REQ_PM_SUSPEND (1 << __REQ_PM_SUSPEND)
#define REQ_PM_RESUME (1 << __REQ_PM_RESUME)
#define REQ_PM_SHUTDOWN (1 << __REQ_PM_SHUTDOWN)
#define REQ_ORDERED_COLOR (1 << __REQ_ORDERED_COLOR)
#define REQ_RW_SYNC (1 << __REQ_RW_SYNC)

struct request_pm_state
{

 int pm_step;

 u32 pm_state;
 void* data;
};

#include <linux/elevator.h>

typedef int (merge_request_fn) (request_queue_t *, struct request *,
 struct bio *);
typedef int (merge_requests_fn) (request_queue_t *, struct request *,
 struct request *);
typedef void (request_fn_proc) (request_queue_t *q);
typedef int (make_request_fn) (request_queue_t *q, struct bio *bio);
typedef int (prep_rq_fn) (request_queue_t *, struct request *);
typedef void (unplug_fn) (request_queue_t *);

struct bio_vec;
typedef int (merge_bvec_fn) (request_queue_t *, struct bio *, struct bio_vec *);
typedef void (activity_fn) (void *data, int rw);
typedef int (issue_flush_fn) (request_queue_t *, struct gendisk *, sector_t *);
typedef void (prepare_flush_fn) (request_queue_t *, struct request *);
typedef void (softirq_done_fn)(struct request *);

enum blk_queue_state {
 Queue_down,
 Queue_up,
};

struct blk_queue_tag {
 struct request **tag_index;
 unsigned long *tag_map;
 struct list_head busy_list;
 int busy;
 int max_depth;
 int real_max_depth;
 atomic_t refcnt;
};

struct request_queue
{

 struct list_head queue_head;
 struct request *last_merge;
 elevator_t *elevator;

 struct request_list rq;

 request_fn_proc *request_fn;
 merge_request_fn *back_merge_fn;
 merge_request_fn *front_merge_fn;
 merge_requests_fn *merge_requests_fn;
 make_request_fn *make_request_fn;
 prep_rq_fn *prep_rq_fn;
 unplug_fn *unplug_fn;
 merge_bvec_fn *merge_bvec_fn;
 activity_fn *activity_fn;
 issue_flush_fn *issue_flush_fn;
 prepare_flush_fn *prepare_flush_fn;
 softirq_done_fn *softirq_done_fn;

 sector_t end_sector;
 struct request *boundary_rq;

 struct timer_list unplug_timer;
 int unplug_thresh;
 unsigned long unplug_delay;
 struct work_struct unplug_work;

 struct backing_dev_info backing_dev_info;

 void *queuedata;

 void *activity_data;

 unsigned long bounce_pfn;
 gfp_t bounce_gfp;

 unsigned long queue_flags;

 spinlock_t __queue_lock;
 spinlock_t *queue_lock;

 struct kobject kobj;

 unsigned long nr_requests;
 unsigned int nr_congestion_on;
 unsigned int nr_congestion_off;
 unsigned int nr_batching;

 unsigned int max_sectors;
 unsigned int max_hw_sectors;
 unsigned short max_phys_segments;
 unsigned short max_hw_segments;
 unsigned short hardsect_size;
 unsigned int max_segment_size;

 unsigned long seg_boundary_mask;
 unsigned int dma_alignment;

 struct blk_queue_tag *queue_tags;

 unsigned int nr_sorted;
 unsigned int in_flight;

 unsigned int sg_timeout;
 unsigned int sg_reserved_size;
 int node;

 struct blk_trace *blk_trace;

 unsigned int ordered, next_ordered, ordseq;
 int orderr, ordcolor;
 struct request pre_flush_rq, bar_rq, post_flush_rq;
 struct request *orig_bar_rq;
 unsigned int bi_size;

 struct mutex sysfs_lock;
};

#define RQ_INACTIVE (-1)
#define RQ_ACTIVE 1

#define QUEUE_FLAG_CLUSTER 0  
#define QUEUE_FLAG_QUEUED 1  
#define QUEUE_FLAG_STOPPED 2  
#define QUEUE_FLAG_READFULL 3  
#define QUEUE_FLAG_WRITEFULL 4  
#define QUEUE_FLAG_DEAD 5  
#define QUEUE_FLAG_REENTER 6  
#define QUEUE_FLAG_PLUGGED 7  
#define QUEUE_FLAG_ELVSWITCH 8  

enum {

 QUEUE_ORDERED_NONE = 0x00,
 QUEUE_ORDERED_DRAIN = 0x01,
 QUEUE_ORDERED_TAG = 0x02,

 QUEUE_ORDERED_PREFLUSH = 0x10,
 QUEUE_ORDERED_POSTFLUSH = 0x20,
 QUEUE_ORDERED_FUA = 0x40,

 QUEUE_ORDERED_DRAIN_FLUSH = QUEUE_ORDERED_DRAIN |
 QUEUE_ORDERED_PREFLUSH | QUEUE_ORDERED_POSTFLUSH,
 QUEUE_ORDERED_DRAIN_FUA = QUEUE_ORDERED_DRAIN |
 QUEUE_ORDERED_PREFLUSH | QUEUE_ORDERED_FUA,
 QUEUE_ORDERED_TAG_FLUSH = QUEUE_ORDERED_TAG |
 QUEUE_ORDERED_PREFLUSH | QUEUE_ORDERED_POSTFLUSH,
 QUEUE_ORDERED_TAG_FUA = QUEUE_ORDERED_TAG |
 QUEUE_ORDERED_PREFLUSH | QUEUE_ORDERED_FUA,

 QUEUE_ORDSEQ_STARTED = 0x01,
 QUEUE_ORDSEQ_DRAIN = 0x02,
 QUEUE_ORDSEQ_PREFLUSH = 0x04,
 QUEUE_ORDSEQ_BAR = 0x08,
 QUEUE_ORDSEQ_POSTFLUSH = 0x10,
 QUEUE_ORDSEQ_DONE = 0x20,
};

#define blk_queue_plugged(q) test_bit(QUEUE_FLAG_PLUGGED, &(q)->queue_flags)
#define blk_queue_tagged(q) test_bit(QUEUE_FLAG_QUEUED, &(q)->queue_flags)
#define blk_queue_stopped(q) test_bit(QUEUE_FLAG_STOPPED, &(q)->queue_flags)
#define blk_queue_flushing(q) ((q)->ordseq)

#define blk_fs_request(rq) ((rq)->flags & REQ_CMD)
#define blk_pc_request(rq) ((rq)->flags & REQ_BLOCK_PC)
#define blk_noretry_request(rq) ((rq)->flags & REQ_FAILFAST)
#define blk_rq_started(rq) ((rq)->flags & REQ_STARTED)

#define blk_account_rq(rq) (blk_rq_started(rq) && blk_fs_request(rq))

#define blk_pm_suspend_request(rq) ((rq)->flags & REQ_PM_SUSPEND)
#define blk_pm_resume_request(rq) ((rq)->flags & REQ_PM_RESUME)
#define blk_pm_request(rq)   ((rq)->flags & (REQ_PM_SUSPEND | REQ_PM_RESUME))

#define blk_sorted_rq(rq) ((rq)->flags & REQ_SORTED)
#define blk_barrier_rq(rq) ((rq)->flags & REQ_HARDBARRIER)
#define blk_fua_rq(rq) ((rq)->flags & REQ_FUA)

#define list_entry_rq(ptr) list_entry((ptr), struct request, queuelist)

#define rq_data_dir(rq) ((rq)->flags & 1)

#define RQ_NOMERGE_FLAGS   (REQ_NOMERGE | REQ_STARTED | REQ_HARDBARRIER | REQ_SOFTBARRIER)
#define rq_mergeable(rq)   (!((rq)->flags & RQ_NOMERGE_FLAGS) && blk_fs_request((rq)))
#define blk_queue_headactive(q, head_active)
#define BLKPREP_OK 0  
#define BLKPREP_KILL 1  
#define BLKPREP_DEFER 2  

#define BLK_BOUNCE_HIGH ((u64)blk_max_low_pfn << PAGE_SHIFT)
#define BLK_BOUNCE_ANY ((u64)blk_max_pfn << PAGE_SHIFT)
#define BLK_BOUNCE_ISA (ISA_DMA_THRESHOLD)

#define rq_for_each_bio(_bio, rq)   if ((rq->bio))   for (_bio = (rq)->bio; _bio; _bio = _bio->bi_next)

#define end_io_error(uptodate) (unlikely((uptodate) <= 0))

#define blk_queue_tag_depth(q) ((q)->queue_tags->busy)
#define blk_queue_tag_queue(q) ((q)->queue_tags->busy < (q)->queue_tags->max_depth)
#define blk_rq_tagged(rq) ((rq)->flags & REQ_QUEUED)

#define MAX_PHYS_SEGMENTS 128
#define MAX_HW_SEGMENTS 128
#define SAFE_MAX_SECTORS 255
#define BLK_DEF_MAX_SECTORS 1024

#define MAX_SEGMENT_SIZE 65536

#define blkdev_entry_to_request(entry) list_entry((entry), struct request, queuelist)

#define blk_finished_io(nsects) do { } while (0)
#define blk_started_io(nsects) do { } while (0)

#define sector_div(n, b)(  {   int _res;   _res = (n) % (b);   (n) /= (b);   _res;  }  )

#define MODULE_ALIAS_BLOCKDEV(major,minor)   MODULE_ALIAS("block-major-" __stringify(major) "-" __stringify(minor))
#define MODULE_ALIAS_BLOCKDEV_MAJOR(major)   MODULE_ALIAS("block-major-" __stringify(major) "-*")

#endif
