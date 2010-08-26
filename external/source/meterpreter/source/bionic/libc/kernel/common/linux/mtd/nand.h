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
#ifndef __LINUX_MTD_NAND_H
#define __LINUX_MTD_NAND_H

#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/mtd/mtd.h>

struct mtd_info;

#define NAND_MAX_CHIPS 8

#define NAND_MAX_OOBSIZE 64
#define NAND_MAX_PAGESIZE 2048

#define NAND_NCE 0x01

#define NAND_CLE 0x02

#define NAND_ALE 0x04

#define NAND_CTRL_CLE (NAND_NCE | NAND_CLE)
#define NAND_CTRL_ALE (NAND_NCE | NAND_ALE)
#define NAND_CTRL_CHANGE 0x80

#define NAND_CMD_READ0 0
#define NAND_CMD_READ1 1
#define NAND_CMD_RNDOUT 5
#define NAND_CMD_PAGEPROG 0x10
#define NAND_CMD_READOOB 0x50
#define NAND_CMD_ERASE1 0x60
#define NAND_CMD_STATUS 0x70
#define NAND_CMD_STATUS_MULTI 0x71
#define NAND_CMD_SEQIN 0x80
#define NAND_CMD_RNDIN 0x85
#define NAND_CMD_READID 0x90
#define NAND_CMD_ERASE2 0xd0
#define NAND_CMD_RESET 0xff

#define NAND_CMD_READSTART 0x30
#define NAND_CMD_RNDOUTSTART 0xE0
#define NAND_CMD_CACHEDPROG 0x15

#define NAND_CMD_DEPLETE1 0x100
#define NAND_CMD_DEPLETE2 0x38
#define NAND_CMD_STATUS_MULTI 0x71
#define NAND_CMD_STATUS_ERROR 0x72

#define NAND_CMD_STATUS_ERROR0 0x73
#define NAND_CMD_STATUS_ERROR1 0x74
#define NAND_CMD_STATUS_ERROR2 0x75
#define NAND_CMD_STATUS_ERROR3 0x76
#define NAND_CMD_STATUS_RESET 0x7f
#define NAND_CMD_STATUS_CLEAR 0xff

#define NAND_CMD_NONE -1

#define NAND_STATUS_FAIL 0x01
#define NAND_STATUS_FAIL_N1 0x02
#define NAND_STATUS_TRUE_READY 0x20
#define NAND_STATUS_READY 0x40
#define NAND_STATUS_WP 0x80

typedef enum {
 NAND_ECC_NONE,
 NAND_ECC_SOFT,
 NAND_ECC_HW,
 NAND_ECC_HW_SYNDROME,
} nand_ecc_modes_t;

#define NAND_ECC_READ 0

#define NAND_ECC_WRITE 1

#define NAND_ECC_READSYN 2

#define NAND_GET_DEVICE 0x80

#define NAND_NO_AUTOINCR 0x00000001

#define NAND_BUSWIDTH_16 0x00000002

#define NAND_NO_PADDING 0x00000004

#define NAND_CACHEPRG 0x00000008

#define NAND_COPYBACK 0x00000010

#define NAND_IS_AND 0x00000020

#define NAND_4PAGE_ARRAY 0x00000040

#define BBT_AUTO_REFRESH 0x00000080

#define NAND_NO_READRDY 0x00000100

#define NAND_SAMSUNG_LP_OPTIONS   (NAND_NO_PADDING | NAND_CACHEPRG | NAND_COPYBACK)

#define NAND_CANAUTOINCR(chip) (!(chip->options & NAND_NO_AUTOINCR))
#define NAND_MUST_PAD(chip) (!(chip->options & NAND_NO_PADDING))
#define NAND_HAS_CACHEPROG(chip) ((chip->options & NAND_CACHEPRG))
#define NAND_HAS_COPYBACK(chip) ((chip->options & NAND_COPYBACK))

#define NAND_CHIPOPTIONS_MSK (0x0000ffff & ~NAND_NO_AUTOINCR)

#define NAND_USE_FLASH_BBT 0x00010000

#define NAND_SKIP_BBTSCAN 0x00020000

#define NAND_CONTROLLER_ALLOC 0x80000000

typedef enum {
 FL_READY,
 FL_READING,
 FL_WRITING,
 FL_ERASING,
 FL_SYNCING,
 FL_CACHEDPRG,
 FL_PM_SUSPENDED,
} nand_state_t;

struct nand_chip;

struct nand_hw_control {
 spinlock_t lock;
 struct nand_chip *active;
 wait_queue_head_t wq;
};

struct nand_ecc_ctrl {
 nand_ecc_modes_t mode;
 int steps;
 int size;
 int bytes;
 int total;
 int prepad;
 int postpad;
 struct nand_ecclayout *layout;
 void (*hwctl)(struct mtd_info *mtd, int mode);
 int (*calculate)(struct mtd_info *mtd,
 const uint8_t *dat,
 uint8_t *ecc_code);
 int (*correct)(struct mtd_info *mtd, uint8_t *dat,
 uint8_t *read_ecc,
 uint8_t *calc_ecc);
 int (*read_page)(struct mtd_info *mtd,
 struct nand_chip *chip,
 uint8_t *buf);
 void (*write_page)(struct mtd_info *mtd,
 struct nand_chip *chip,
 const uint8_t *buf);
 int (*read_oob)(struct mtd_info *mtd,
 struct nand_chip *chip,
 int page,
 int sndcmd);
 int (*write_oob)(struct mtd_info *mtd,
 struct nand_chip *chip,
 int page);
};

struct nand_buffers {
 uint8_t ecccalc[NAND_MAX_OOBSIZE];
 uint8_t ecccode[NAND_MAX_OOBSIZE];
 uint8_t oobwbuf[NAND_MAX_OOBSIZE];
 uint8_t databuf[NAND_MAX_PAGESIZE];
 uint8_t oobrbuf[NAND_MAX_OOBSIZE];
};

struct nand_chip {
 void __iomem *IO_ADDR_R;
 void __iomem *IO_ADDR_W;

 uint8_t (*read_byte)(struct mtd_info *mtd);
 u16 (*read_word)(struct mtd_info *mtd);
 void (*write_buf)(struct mtd_info *mtd, const uint8_t *buf, int len);
 void (*read_buf)(struct mtd_info *mtd, uint8_t *buf, int len);
 int (*verify_buf)(struct mtd_info *mtd, const uint8_t *buf, int len);
 void (*select_chip)(struct mtd_info *mtd, int chip);
 int (*block_bad)(struct mtd_info *mtd, loff_t ofs, int getchip);
 int (*block_markbad)(struct mtd_info *mtd, loff_t ofs);
 void (*cmd_ctrl)(struct mtd_info *mtd, int dat,
 unsigned int ctrl);
 int (*dev_ready)(struct mtd_info *mtd);
 void (*cmdfunc)(struct mtd_info *mtd, unsigned command, int column, int page_addr);
 int (*waitfunc)(struct mtd_info *mtd, struct nand_chip *this);
 void (*erase_cmd)(struct mtd_info *mtd, int page);
 int (*scan_bbt)(struct mtd_info *mtd);
 int (*errstat)(struct mtd_info *mtd, struct nand_chip *this, int state, int status, int page);

 int chip_delay;
 unsigned int options;

 int page_shift;
 int phys_erase_shift;
 int bbt_erase_shift;
 int chip_shift;
 int numchips;
 unsigned long chipsize;
 int pagemask;
 int pagebuf;
 int badblockpos;

 nand_state_t state;

 uint8_t *oob_poi;
 struct nand_hw_control *controller;
 struct nand_ecclayout *ecclayout;

 struct nand_ecc_ctrl ecc;
 struct nand_buffers buffers;
 struct nand_hw_control hwcontrol;

 struct mtd_oob_ops ops;

 uint8_t *bbt;
 struct nand_bbt_descr *bbt_td;
 struct nand_bbt_descr *bbt_md;

 struct nand_bbt_descr *badblock_pattern;

 void *priv;
};

#define NAND_MFR_TOSHIBA 0x98
#define NAND_MFR_SAMSUNG 0xec
#define NAND_MFR_FUJITSU 0x04
#define NAND_MFR_NATIONAL 0x8f
#define NAND_MFR_RENESAS 0x07
#define NAND_MFR_STMICRO 0x20
#define NAND_MFR_HYNIX 0xad

struct nand_flash_dev {
 char *name;
 int id;
 unsigned long pagesize;
 unsigned long chipsize;
 unsigned long erasesize;
 unsigned long options;
};

struct nand_manufacturers {
 int id;
 char * name;
};

struct nand_bbt_descr {
 int options;
 int pages[NAND_MAX_CHIPS];
 int offs;
 int veroffs;
 uint8_t version[NAND_MAX_CHIPS];
 int len;
 int maxblocks;
 int reserved_block_code;
 uint8_t *pattern;
};

#define NAND_BBT_NRBITS_MSK 0x0000000F
#define NAND_BBT_1BIT 0x00000001
#define NAND_BBT_2BIT 0x00000002
#define NAND_BBT_4BIT 0x00000004
#define NAND_BBT_8BIT 0x00000008

#define NAND_BBT_LASTBLOCK 0x00000010

#define NAND_BBT_ABSPAGE 0x00000020

#define NAND_BBT_SEARCH 0x00000040

#define NAND_BBT_PERCHIP 0x00000080

#define NAND_BBT_VERSION 0x00000100

#define NAND_BBT_CREATE 0x00000200

#define NAND_BBT_SCANALLPAGES 0x00000400

#define NAND_BBT_SCANEMPTY 0x00000800

#define NAND_BBT_WRITE 0x00001000

#define NAND_BBT_SAVECONTENT 0x00002000

#define NAND_BBT_SCAN2NDPAGE 0x00004000

#define NAND_BBT_SCAN_MAXBLOCKS 4

#define NAND_SMALL_BADBLOCK_POS 5
#define NAND_LARGE_BADBLOCK_POS 0

struct platform_nand_chip {
 int nr_chips;
 int chip_offset;
 int nr_partitions;
 struct mtd_partition *partitions;
 struct nand_ecclayout *ecclayout;
 int chip_delay;
 unsigned int options;
 void *priv;
};

struct platform_nand_ctrl {
 void (*hwcontrol)(struct mtd_info *mtd, int cmd);
 int (*dev_ready)(struct mtd_info *mtd);
 void (*select_chip)(struct mtd_info *mtd, int chip);
 void *priv;
};

#endif
