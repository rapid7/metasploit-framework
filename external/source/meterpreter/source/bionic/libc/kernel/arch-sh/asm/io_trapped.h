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
#ifndef __ASM_SH_IO_TRAPPED_H
#define __ASM_SH_IO_TRAPPED_H

#include <linux/list.h>
#include <linux/ioport.h>
#include <asm/page.h>

#define IO_TRAPPED_MAGIC 0xfeedbeef

struct trapped_io {
 unsigned int magic;
 struct resource *resource;
 unsigned int num_resources;
 unsigned int minimum_bus_width;
 struct list_head list;
 void __iomem *virt_base;
} __aligned(PAGE_SIZE);

#define register_trapped_io(tiop) (-1)
#define handle_trapped_io(tiop, address) 0
#define __ioremap_trapped(offset, size) NULL
#define __ioport_map_trapped(offset, size) NULL

#endif
