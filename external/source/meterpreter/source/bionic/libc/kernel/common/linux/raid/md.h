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
#ifndef _MD_H
#define _MD_H

#include <linux/blkdev.h>
#include <asm/semaphore.h>
#include <linux/major.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/hdreg.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/smp_lock.h>
#include <linux/delay.h>
#include <net/checksum.h>
#include <linux/random.h>
#include <linux/kernel_stat.h>
#include <asm/io.h>
#include <linux/completion.h>
#include <linux/mempool.h>
#include <linux/list.h>
#include <linux/reboot.h>
#include <linux/vmalloc.h>
#include <linux/blkpg.h>
#include <linux/bio.h>

#include <linux/raid/md_p.h>
#include <linux/raid/md_u.h>
#include <linux/raid/md_k.h>

#define MD_MAJOR_VERSION 0
#define MD_MINOR_VERSION 90

#define MD_PATCHLEVEL_VERSION 3

#endif

