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
#ifndef __MTD_ABI_H__
#define __MTD_ABI_H__

struct erase_info_user {
 uint32_t start;
 uint32_t length;
};

struct mtd_oob_buf {
 uint32_t start;
 uint32_t length;
 unsigned char __user *ptr;
};

#define MTD_ABSENT 0
#define MTD_RAM 1
#define MTD_ROM 2
#define MTD_NORFLASH 3
#define MTD_NANDFLASH 4
#define MTD_DATAFLASH 6

#define MTD_WRITEABLE 0x400  
#define MTD_BIT_WRITEABLE 0x800  
#define MTD_NO_ERASE 0x1000  
#define MTD_STUPID_LOCK 0x2000  

#define MTD_CAP_ROM 0
#define MTD_CAP_RAM (MTD_WRITEABLE | MTD_BIT_WRITEABLE | MTD_NO_ERASE)
#define MTD_CAP_NORFLASH (MTD_WRITEABLE | MTD_BIT_WRITEABLE)
#define MTD_CAP_NANDFLASH (MTD_WRITEABLE)

#define MTD_NANDECC_OFF 0 
#define MTD_NANDECC_PLACE 1 
#define MTD_NANDECC_AUTOPLACE 2 
#define MTD_NANDECC_PLACEONLY 3 
#define MTD_NANDECC_AUTOPL_USR 4 

#define MTD_OTP_OFF 0
#define MTD_OTP_FACTORY 1
#define MTD_OTP_USER 2

struct mtd_info_user {
 uint8_t type;
 uint32_t flags;
 uint32_t size;
 uint32_t erasesize;
 uint32_t writesize;
 uint32_t oobsize;

 uint32_t ecctype;
 uint32_t eccsize;
};

struct region_info_user {
 uint32_t offset;
 uint32_t erasesize;
 uint32_t numblocks;
 uint32_t regionindex;
};

struct otp_info {
 uint32_t start;
 uint32_t length;
 uint32_t locked;
};

#define MEMGETINFO _IOR('M', 1, struct mtd_info_user)
#define MEMERASE _IOW('M', 2, struct erase_info_user)
#define MEMWRITEOOB _IOWR('M', 3, struct mtd_oob_buf)
#define MEMREADOOB _IOWR('M', 4, struct mtd_oob_buf)
#define MEMLOCK _IOW('M', 5, struct erase_info_user)
#define MEMUNLOCK _IOW('M', 6, struct erase_info_user)
#define MEMGETREGIONCOUNT _IOR('M', 7, int)
#define MEMGETREGIONINFO _IOWR('M', 8, struct region_info_user)
#define MEMSETOOBSEL _IOW('M', 9, struct nand_oobinfo)
#define MEMGETOOBSEL _IOR('M', 10, struct nand_oobinfo)
#define MEMGETBADBLOCK _IOW('M', 11, loff_t)
#define MEMSETBADBLOCK _IOW('M', 12, loff_t)
#define OTPSELECT _IOR('M', 13, int)
#define OTPGETREGIONCOUNT _IOW('M', 14, int)
#define OTPGETREGIONINFO _IOW('M', 15, struct otp_info)
#define OTPLOCK _IOR('M', 16, struct otp_info)
#define ECCGETLAYOUT _IOR('M', 17, struct nand_ecclayout)
#define ECCGETSTATS _IOR('M', 18, struct mtd_ecc_stats)
#define MTDFILEMODE _IO('M', 19)

struct nand_oobinfo {
 uint32_t useecc;
 uint32_t eccbytes;
 uint32_t oobfree[8][2];
 uint32_t eccpos[32];
};

struct nand_oobfree {
 uint32_t offset;
 uint32_t length;
};

#define MTD_MAX_OOBFREE_ENTRIES 8

struct nand_ecclayout {
 uint32_t eccbytes;
 uint32_t eccpos[64];
 uint32_t oobavail;
 struct nand_oobfree oobfree[MTD_MAX_OOBFREE_ENTRIES];
};

struct mtd_ecc_stats {
 uint32_t corrected;
 uint32_t failed;
 uint32_t badblocks;
 uint32_t bbtblocks;
};

enum mtd_file_modes {
 MTD_MODE_NORMAL = MTD_OTP_OFF,
 MTD_MODE_OTP_FACTORY = MTD_OTP_FACTORY,
 MTD_MODE_OTP_USER = MTD_OTP_USER,
 MTD_MODE_RAW,
};

#endif
