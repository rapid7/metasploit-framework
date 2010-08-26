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
#ifndef _LINUX_TASKSTATS_H
#define _LINUX_TASKSTATS_H

#define TASKSTATS_VERSION 1

struct taskstats {

 __u16 version;
 __u16 padding[3];

 __u64 cpu_count;
 __u64 cpu_delay_total;

 __u64 blkio_count;
 __u64 blkio_delay_total;

 __u64 swapin_count;
 __u64 swapin_delay_total;

 __u64 cpu_run_real_total;

 __u64 cpu_run_virtual_total;

};

enum {
 TASKSTATS_CMD_UNSPEC = 0,
 TASKSTATS_CMD_GET,
 TASKSTATS_CMD_NEW,
 __TASKSTATS_CMD_MAX,
};

#define TASKSTATS_CMD_MAX (__TASKSTATS_CMD_MAX - 1)

enum {
 TASKSTATS_TYPE_UNSPEC = 0,
 TASKSTATS_TYPE_PID,
 TASKSTATS_TYPE_TGID,
 TASKSTATS_TYPE_STATS,
 TASKSTATS_TYPE_AGGR_PID,
 TASKSTATS_TYPE_AGGR_TGID,
 __TASKSTATS_TYPE_MAX,
};

#define TASKSTATS_TYPE_MAX (__TASKSTATS_TYPE_MAX - 1)

enum {
 TASKSTATS_CMD_ATTR_UNSPEC = 0,
 TASKSTATS_CMD_ATTR_PID,
 TASKSTATS_CMD_ATTR_TGID,
 TASKSTATS_CMD_ATTR_REGISTER_CPUMASK,
 TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK,
 __TASKSTATS_CMD_ATTR_MAX,
};

#define TASKSTATS_CMD_ATTR_MAX (__TASKSTATS_CMD_ATTR_MAX - 1)

#define TASKSTATS_GENL_NAME "TASKSTATS"
#define TASKSTATS_GENL_VERSION 0x1

#endif
