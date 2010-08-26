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
#ifndef __ASM_SH_DMA_MAPPING_H
#define __ASM_SH_DMA_MAPPING_H

#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm-generic/dma-coherent.h>

#define dma_supported(dev, mask) (1)

#define dma_alloc_noncoherent(d, s, h, f) dma_alloc_coherent(d, s, h, f)
#define dma_free_noncoherent(d, s, v, h) dma_free_coherent(d, s, v, h)
#define dma_is_consistent(d, h) (1)

#define dma_unmap_single(dev, addr, size, dir) do { } while (0)
#define dma_unmap_sg(dev, sg, nents, dir) do { } while (0)
#define ARCH_HAS_DMA_DECLARE_COHERENT_MEMORY

#endif
