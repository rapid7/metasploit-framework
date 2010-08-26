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
#ifndef __MTD_TRANS_H__
#define __MTD_TRANS_H__

#include <linux/mutex.h>

struct hd_geometry;
struct mtd_info;
struct mtd_blktrans_ops;
struct file;
struct inode;

struct mtd_blktrans_dev {
 struct mtd_blktrans_ops *tr;
 struct list_head list;
 struct mtd_info *mtd;
 struct mutex lock;
 int devnum;
 int blksize;
 unsigned long size;
 int readonly;
 void *blkcore_priv;
};

struct blkcore_priv;

struct mtd_blktrans_ops {
 char *name;
 int major;
 int part_bits;

 int (*readsect)(struct mtd_blktrans_dev *dev,
 unsigned long block, char *buffer);
 int (*writesect)(struct mtd_blktrans_dev *dev,
 unsigned long block, char *buffer);

 int (*getgeo)(struct mtd_blktrans_dev *dev, struct hd_geometry *geo);
 int (*flush)(struct mtd_blktrans_dev *dev);

 int (*open)(struct mtd_blktrans_dev *dev);
 int (*release)(struct mtd_blktrans_dev *dev);

 void (*add_mtd)(struct mtd_blktrans_ops *tr, struct mtd_info *mtd);
 void (*remove_dev)(struct mtd_blktrans_dev *dev);

 struct list_head devs;
 struct list_head list;
 struct module *owner;

 struct mtd_blkcore_priv *blkcore_priv;
};

#endif
