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
#ifndef _LINUX_IOPORT_H
#define _LINUX_IOPORT_H

#include <linux/compiler.h>
#include <linux/types.h>

struct resource {
 resource_size_t start;
 resource_size_t end;
 const char *name;
 unsigned long flags;
 struct resource *parent, *sibling, *child;
};

struct resource_list {
 struct resource_list *next;
 struct resource *res;
 struct pci_dev *dev;
};

#define IORESOURCE_BITS 0x000000ff  

#define IORESOURCE_IO 0x00000100  
#define IORESOURCE_MEM 0x00000200
#define IORESOURCE_IRQ 0x00000400
#define IORESOURCE_DMA 0x00000800

#define IORESOURCE_PREFETCH 0x00001000  
#define IORESOURCE_READONLY 0x00002000
#define IORESOURCE_CACHEABLE 0x00004000
#define IORESOURCE_RANGELENGTH 0x00008000
#define IORESOURCE_SHADOWABLE 0x00010000
#define IORESOURCE_BUS_HAS_VGA 0x00080000

#define IORESOURCE_DISABLED 0x10000000
#define IORESOURCE_UNSET 0x20000000
#define IORESOURCE_AUTO 0x40000000
#define IORESOURCE_BUSY 0x80000000  

#define IORESOURCE_IRQ_HIGHEDGE (1<<0)
#define IORESOURCE_IRQ_LOWEDGE (1<<1)
#define IORESOURCE_IRQ_HIGHLEVEL (1<<2)
#define IORESOURCE_IRQ_LOWLEVEL (1<<3)
#define IORESOURCE_IRQ_SHAREABLE (1<<4)

#define IORESOURCE_DMA_TYPE_MASK (3<<0)
#define IORESOURCE_DMA_8BIT (0<<0)
#define IORESOURCE_DMA_8AND16BIT (1<<0)
#define IORESOURCE_DMA_16BIT (2<<0)

#define IORESOURCE_DMA_MASTER (1<<2)
#define IORESOURCE_DMA_BYTE (1<<3)
#define IORESOURCE_DMA_WORD (1<<4)

#define IORESOURCE_DMA_SPEED_MASK (3<<6)
#define IORESOURCE_DMA_COMPATIBLE (0<<6)
#define IORESOURCE_DMA_TYPEA (1<<6)
#define IORESOURCE_DMA_TYPEB (2<<6)
#define IORESOURCE_DMA_TYPEF (3<<6)

#define IORESOURCE_MEM_WRITEABLE (1<<0)  
#define IORESOURCE_MEM_CACHEABLE (1<<1)  
#define IORESOURCE_MEM_RANGELENGTH (1<<2)  
#define IORESOURCE_MEM_TYPE_MASK (3<<3)
#define IORESOURCE_MEM_8BIT (0<<3)
#define IORESOURCE_MEM_16BIT (1<<3)
#define IORESOURCE_MEM_8AND16BIT (2<<3)
#define IORESOURCE_MEM_32BIT (3<<3)
#define IORESOURCE_MEM_SHADOWABLE (1<<5)  
#define IORESOURCE_MEM_EXPANSIONROM (1<<6)

#define IORESOURCE_ROM_ENABLE (1<<0)  
#define IORESOURCE_ROM_SHADOW (1<<1)  
#define IORESOURCE_ROM_COPY (1<<2)  

#define request_region(start,n,name) __request_region(&ioport_resource, (start), (n), (name))
#define request_mem_region(start,n,name) __request_region(&iomem_resource, (start), (n), (name))
#define rename_region(region, newname) do { (region)->name = (newname); } while (0)

#define release_region(start,n) __release_region(&ioport_resource, (start), (n))
#define check_mem_region(start,n) __check_region(&iomem_resource, (start), (n))
#define release_mem_region(start,n) __release_region(&iomem_resource, (start), (n))

#endif
