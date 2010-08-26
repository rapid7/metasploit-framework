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
#ifndef __ASM_SPI_H__
#define __ASM_SPI_H__

struct sh_spi_info;

struct sh_spi_info {
 int bus_num;
 int num_chipselect;

 void (*chip_select)(struct sh_spi_info *spi, int cs, int state);
};

#endif
