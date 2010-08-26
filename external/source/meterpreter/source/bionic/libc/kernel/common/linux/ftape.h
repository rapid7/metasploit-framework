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
#ifndef _FTAPE_H
#define _FTAPE_H

#define FTAPE_VERSION "ftape v3.04d 25/11/97"

#include <linux/types.h>
#include <linux/mtio.h>

#define FT_SECTOR(x) (x+1)  
#define FT_SECTOR_SIZE 1024
#define FT_SECTORS_PER_SEGMENT 32
#define FT_ECC_SECTORS 3
#define FT_SEGMENT_SIZE ((FT_SECTORS_PER_SEGMENT - FT_ECC_SECTORS) * FT_SECTOR_SIZE)
#define FT_BUFF_SIZE (FT_SECTORS_PER_SEGMENT * FT_SECTOR_SIZE)

#define FTAPE_SEL_A 0
#define FTAPE_SEL_B 1
#define FTAPE_SEL_C 2
#define FTAPE_SEL_D 3
#define FTAPE_SEL_MASK 3
#define FTAPE_SEL(unit) ((unit) & FTAPE_SEL_MASK)
#define FTAPE_NO_REWIND 4  

typedef union {
 struct {
 __u8 error;
 __u8 command;
 } error;
 long space;
} ft_drive_error;
typedef union {
 struct {
 __u8 drive_status;
 __u8 drive_config;
 __u8 tape_status;
 } status;
 long space;
} ft_drive_status;

#endif
