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
#ifndef __MTD_MTD_H__
#define __MTD_MTD_H__

#error This is a kernel header. Perhaps include mtd-user.h instead?

#include <linux/types.h>
#include <linux/module.h>
#include <linux/uio.h>
#include <linux/notifier.h>

#include <linux/mtd/compatmac.h>
#include <mtd/mtd-abi.h>

#define MTD_CHAR_MAJOR 90
#define MTD_BLOCK_MAJOR 31
#define MAX_MTD_DEVICES 16

#define MTD_ERASE_PENDING 0x01
#define MTD_ERASING 0x02
#define MTD_ERASE_SUSPEND 0x04
#define MTD_ERASE_DONE 0x08
#define MTD_ERASE_FAILED 0x10

struct erase_info {
 struct mtd_info *mtd;
 u_int32_t addr;
 u_int32_t len;
 u_int32_t fail_addr;
 u_long time;
 u_long retries;
 u_int dev;
 u_int cell;
 void (*callback) (struct erase_info *self);
 u_long priv;
 u_char state;
 struct erase_info *next;
};

struct mtd_erase_region_info {
 u_int32_t offset;
 u_int32_t erasesize;
 u_int32_t numblocks;
};

typedef enum {
 MTD_OOB_PLACE,
 MTD_OOB_AUTO,
 MTD_OOB_RAW,
} mtd_oob_mode_t;

struct mtd_oob_ops {
 mtd_oob_mode_t mode;
 size_t len;
 size_t retlen;
 size_t ooblen;
 uint32_t ooboffs;
 uint8_t *datbuf;
 uint8_t *oobbuf;
};

struct mtd_info {
 u_char type;
 u_int32_t flags;
 u_int32_t size;

 u_int32_t erasesize;

 u_int32_t writesize;

 u_int32_t oobsize;
 u_int32_t ecctype;
 u_int32_t eccsize;

#define MTD_PROGREGION_CTRLMODE_VALID(mtd) (mtd)->oobsize
#define MTD_PROGREGION_CTRLMODE_INVALID(mtd) (mtd)->ecctype

 char *name;
 int index;

 struct nand_ecclayout *ecclayout;

 int numeraseregions;
 struct mtd_erase_region_info *eraseregions;

 u_int32_t bank_size;

 int (*erase) (struct mtd_info *mtd, struct erase_info *instr);

 int (*point) (struct mtd_info *mtd, loff_t from, size_t len, size_t *retlen, u_char **mtdbuf);

 void (*unpoint) (struct mtd_info *mtd, u_char * addr, loff_t from, size_t len);

 int (*read) (struct mtd_info *mtd, loff_t from, size_t len, size_t *retlen, u_char *buf);
 int (*write) (struct mtd_info *mtd, loff_t to, size_t len, size_t *retlen, const u_char *buf);

 int (*read_oob) (struct mtd_info *mtd, loff_t from,
 struct mtd_oob_ops *ops);
 int (*write_oob) (struct mtd_info *mtd, loff_t to,
 struct mtd_oob_ops *ops);

 int (*get_fact_prot_info) (struct mtd_info *mtd, struct otp_info *buf, size_t len);
 int (*read_fact_prot_reg) (struct mtd_info *mtd, loff_t from, size_t len, size_t *retlen, u_char *buf);
 int (*get_user_prot_info) (struct mtd_info *mtd, struct otp_info *buf, size_t len);
 int (*read_user_prot_reg) (struct mtd_info *mtd, loff_t from, size_t len, size_t *retlen, u_char *buf);
 int (*write_user_prot_reg) (struct mtd_info *mtd, loff_t from, size_t len, size_t *retlen, u_char *buf);
 int (*lock_user_prot_reg) (struct mtd_info *mtd, loff_t from, size_t len);

 int (*writev) (struct mtd_info *mtd, const struct kvec *vecs, unsigned long count, loff_t to, size_t *retlen);

 void (*sync) (struct mtd_info *mtd);

 int (*lock) (struct mtd_info *mtd, loff_t ofs, size_t len);
 int (*unlock) (struct mtd_info *mtd, loff_t ofs, size_t len);

 int (*suspend) (struct mtd_info *mtd);
 void (*resume) (struct mtd_info *mtd);

 int (*block_isbad) (struct mtd_info *mtd, loff_t ofs);
 int (*block_markbad) (struct mtd_info *mtd, loff_t ofs);

 struct notifier_block reboot_notifier;

 struct mtd_ecc_stats ecc_stats;

 void *priv;

 struct module *owner;
 int usecount;
};

struct mtd_notifier {
 void (*add)(struct mtd_info *mtd);
 void (*remove)(struct mtd_info *mtd);
 struct list_head list;
};

#define MTD_DEBUG_LEVEL0 (0)  
#define MTD_DEBUG_LEVEL1 (1)  
#define MTD_DEBUG_LEVEL2 (2)  
#define MTD_DEBUG_LEVEL3 (3)  
#define DEBUG(n, args...) do { } while(0)
#endif
