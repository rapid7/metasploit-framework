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
#ifndef __MTD_NFTL_H__
#define __MTD_NFTL_H__

#include <linux/mtd/mtd.h>
#include <linux/mtd/blktrans.h>

#include <mtd/nftl-user.h>

#define BLOCK_NIL 0xffff  
#define BLOCK_FREE 0xfffe  
#define BLOCK_NOTEXPLORED 0xfffd  
#define BLOCK_RESERVED 0xfffc  

struct NFTLrecord {
 struct mtd_blktrans_dev mbd;
 __u16 MediaUnit, SpareMediaUnit;
 __u32 EraseSize;
 struct NFTLMediaHeader MediaHdr;
 int usecount;
 unsigned char heads;
 unsigned char sectors;
 unsigned short cylinders;
 __u16 numvunits;
 __u16 lastEUN;
 __u16 numfreeEUNs;
 __u16 LastFreeEUN;
 int head,sect,cyl;
 __u16 *EUNtable;
 __u16 *ReplUnitTable;
 unsigned int nb_blocks;
 unsigned int nb_boot_blocks;
 struct erase_info instr;
 struct nand_ecclayout oobinfo;
};

#ifndef NFTL_MAJOR
#define NFTL_MAJOR 93
#endif

#define MAX_NFTLS 16
#define MAX_SECTORS_PER_UNIT 64
#define NFTL_PARTN_BITS 4

#endif
