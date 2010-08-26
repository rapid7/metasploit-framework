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
#ifndef __ASM_SH_SCATTERLIST_H
#define __ASM_SH_SCATTERLIST_H

#include <asm/types.h>

struct scatterlist {
 unsigned long page_link;
 unsigned int offset;
 dma_addr_t dma_address;
 unsigned int length;
};

#define ISA_DMA_THRESHOLD PHYS_ADDR_MASK

#define sg_dma_address(sg) ((sg)->dma_address)
#define sg_dma_len(sg) ((sg)->length)

#endif
