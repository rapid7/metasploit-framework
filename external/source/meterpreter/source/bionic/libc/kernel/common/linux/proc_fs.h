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
#ifndef _LINUX_PROC_FS_H
#define _LINUX_PROC_FS_H

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>

#define FIRST_PROCESS_ENTRY 256

enum {
 PROC_ROOT_INO = 1,
};

#define PROC_SUPER_MAGIC 0x9fa0

typedef int (read_proc_t)(char *page, char **start, off_t off,
 int count, int *eof, void *data);
typedef int (write_proc_t)(struct file *file, const char __user *buffer,
 unsigned long count, void *data);
typedef int (get_info_t)(char *, char **, off_t, int);

struct proc_dir_entry {
 unsigned int low_ino;
 unsigned short namelen;
 const char *name;
 mode_t mode;
 nlink_t nlink;
 uid_t uid;
 gid_t gid;
 loff_t size;
 struct inode_operations * proc_iops;
 const struct file_operations * proc_fops;
 get_info_t *get_info;
 struct module *owner;
 struct proc_dir_entry *next, *parent, *subdir;
 void *data;
 read_proc_t *read_proc;
 write_proc_t *write_proc;
 atomic_t count;
 int deleted;
 void *set;
};

struct kcore_list {
 struct kcore_list *next;
 unsigned long addr;
 size_t size;
};

struct vmcore {
 struct list_head list;
 unsigned long long paddr;
 unsigned long long size;
 loff_t offset;
};

#define proc_root_driver NULL
#define proc_net NULL
#define proc_bus NULL

#define proc_net_fops_create(name, mode, fops) ({ (void)(mode), NULL; })
#define proc_net_create(name, mode, info) ({ (void)(mode), NULL; })
#define remove_proc_entry(name, parent) do {} while (0)

#endif
