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
#ifndef MTD_PARTITIONS_H
#define MTD_PARTITIONS_H

#include <linux/types.h>

struct mtd_partition {
 char *name;
 u_int32_t size;
 u_int32_t offset;
 u_int32_t mask_flags;
 struct nand_ecclayout *ecclayout;
 struct mtd_info **mtdp;
};

#define MTDPART_OFS_NXTBLK (-2)
#define MTDPART_OFS_APPEND (-1)
#define MTDPART_SIZ_FULL (0)

struct mtd_part_parser {
 struct list_head list;
 struct module *owner;
 const char *name;
 int (*parse_fn)(struct mtd_info *, struct mtd_partition **, unsigned long);
};

#define put_partition_parser(p) do { module_put((p)->owner); } while(0)

#endif

