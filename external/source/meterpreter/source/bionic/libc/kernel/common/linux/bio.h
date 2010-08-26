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
#ifndef __LINUX_BIO_H
#define __LINUX_BIO_H

#include <linux/highmem.h>
#include <linux/mempool.h>
#include <linux/ioprio.h>

#include <asm/io.h>

#if defined(BIO_VMERGE_MAX_SIZE) && defined(BIO_VMERGE_BOUNDARY)
#define BIOVEC_VIRT_START_SIZE(x) (bvec_to_phys(x) & (BIO_VMERGE_BOUNDARY - 1))
#define BIOVEC_VIRT_OVERSIZE(x) ((x) > BIO_VMERGE_MAX_SIZE)
#else
#define BIOVEC_VIRT_START_SIZE(x) 0
#define BIOVEC_VIRT_OVERSIZE(x) 0
#endif

#ifndef BIO_VMERGE_BOUNDARY
#define BIO_VMERGE_BOUNDARY 0
#endif

#define BIO_DEBUG

#ifdef BIO_DEBUG
#define BIO_BUG_ON BUG_ON
#else
#define BIO_BUG_ON
#endif

#define BIO_MAX_PAGES 256
#define BIO_MAX_SIZE (BIO_MAX_PAGES << PAGE_CACHE_SHIFT)
#define BIO_MAX_SECTORS (BIO_MAX_SIZE >> 9)

struct bio_vec {
 struct page *bv_page;
 unsigned int bv_len;
 unsigned int bv_offset;
};

struct bio_set;
struct bio;
typedef int (bio_end_io_t) (struct bio *, unsigned int, int);
typedef void (bio_destructor_t) (struct bio *);

struct bio {
 sector_t bi_sector;
 struct bio *bi_next;
 struct block_device *bi_bdev;
 unsigned long bi_flags;
 unsigned long bi_rw;

 unsigned short bi_vcnt;
 unsigned short bi_idx;

 unsigned short bi_phys_segments;

 unsigned short bi_hw_segments;

 unsigned int bi_size;

 unsigned int bi_hw_front_size;
 unsigned int bi_hw_back_size;

 unsigned int bi_max_vecs;

 struct bio_vec *bi_io_vec;

 bio_end_io_t *bi_end_io;
 atomic_t bi_cnt;

 void *bi_private;

 bio_destructor_t *bi_destructor;
};

#define BIO_UPTODATE 0  
#define BIO_RW_BLOCK 1  
#define BIO_EOF 2  
#define BIO_SEG_VALID 3  
#define BIO_CLONED 4  
#define BIO_BOUNCED 5  
#define BIO_USER_MAPPED 6  
#define BIO_EOPNOTSUPP 7  
#define bio_flagged(bio, flag) ((bio)->bi_flags & (1 << (flag)))

#define BIO_POOL_BITS (4)
#define BIO_POOL_OFFSET (BITS_PER_LONG - BIO_POOL_BITS)
#define BIO_POOL_MASK (1UL << BIO_POOL_OFFSET)
#define BIO_POOL_IDX(bio) ((bio)->bi_flags >> BIO_POOL_OFFSET) 

#define BIO_RW 0
#define BIO_RW_AHEAD 1
#define BIO_RW_BARRIER 2
#define BIO_RW_FAILFAST 3
#define BIO_RW_SYNC 4

#define BIO_PRIO_SHIFT (8 * sizeof(unsigned long) - IOPRIO_BITS)
#define bio_prio(bio) ((bio)->bi_rw >> BIO_PRIO_SHIFT)
#define bio_prio_valid(bio) ioprio_valid(bio_prio(bio))

#define bio_set_prio(bio, prio) do {   WARN_ON(prio >= (1 << IOPRIO_BITS));   (bio)->bi_rw &= ((1UL << BIO_PRIO_SHIFT) - 1);   (bio)->bi_rw |= ((unsigned long) (prio) << BIO_PRIO_SHIFT);  } while (0)

#define bio_iovec_idx(bio, idx) (&((bio)->bi_io_vec[(idx)]))
#define bio_iovec(bio) bio_iovec_idx((bio), (bio)->bi_idx)
#define bio_page(bio) bio_iovec((bio))->bv_page
#define bio_offset(bio) bio_iovec((bio))->bv_offset
#define bio_segments(bio) ((bio)->bi_vcnt - (bio)->bi_idx)
#define bio_sectors(bio) ((bio)->bi_size >> 9)
#define bio_cur_sectors(bio) (bio_iovec(bio)->bv_len >> 9)
#define bio_data(bio) (page_address(bio_page((bio))) + bio_offset((bio)))
#define bio_barrier(bio) ((bio)->bi_rw & (1 << BIO_RW_BARRIER))
#define bio_sync(bio) ((bio)->bi_rw & (1 << BIO_RW_SYNC))
#define bio_failfast(bio) ((bio)->bi_rw & (1 << BIO_RW_FAILFAST))
#define bio_rw_ahead(bio) ((bio)->bi_rw & (1 << BIO_RW_AHEAD))

#define bio_to_phys(bio) (page_to_phys(bio_page((bio))) + (unsigned long) bio_offset((bio)))
#define bvec_to_phys(bv) (page_to_phys((bv)->bv_page) + (unsigned long) (bv)->bv_offset)

#define __bio_kmap_atomic(bio, idx, kmtype)   (kmap_atomic(bio_iovec_idx((bio), (idx))->bv_page, kmtype) +   bio_iovec_idx((bio), (idx))->bv_offset)

#define __bio_kunmap_atomic(addr, kmtype) kunmap_atomic(addr, kmtype)

#define __BVEC_END(bio) bio_iovec_idx((bio), (bio)->bi_vcnt - 1)
#define __BVEC_START(bio) bio_iovec_idx((bio), (bio)->bi_idx)

#ifndef BIOVEC_PHYS_MERGEABLE
#define BIOVEC_PHYS_MERGEABLE(vec1, vec2)   ((bvec_to_phys((vec1)) + (vec1)->bv_len) == bvec_to_phys((vec2)))
#endif

#define BIOVEC_VIRT_MERGEABLE(vec1, vec2)   ((((bvec_to_phys((vec1)) + (vec1)->bv_len) | bvec_to_phys((vec2))) & (BIO_VMERGE_BOUNDARY - 1)) == 0)
#define __BIO_SEG_BOUNDARY(addr1, addr2, mask)   (((addr1) | (mask)) == (((addr2) - 1) | (mask)))
#define BIOVEC_SEG_BOUNDARY(q, b1, b2)   __BIO_SEG_BOUNDARY(bvec_to_phys((b1)), bvec_to_phys((b2)) + (b2)->bv_len, (q)->seg_boundary_mask)
#define BIO_SEG_BOUNDARY(q, b1, b2)   BIOVEC_SEG_BOUNDARY((q), __BVEC_END((b1)), __BVEC_START((b2)))

#define bio_io_error(bio, bytes) bio_endio((bio), (bytes), -EIO)

#define __bio_for_each_segment(bvl, bio, i, start_idx)   for (bvl = bio_iovec_idx((bio), (start_idx)), i = (start_idx);   i < (bio)->bi_vcnt;   bvl++, i++)

#define bio_for_each_segment(bvl, bio, i)   __bio_for_each_segment(bvl, bio, i, (bio)->bi_idx)

#define bio_get(bio) atomic_inc(&(bio)->bi_cnt)

struct bio_pair {
 struct bio bio1, bio2;
 struct bio_vec bv1, bv2;
 atomic_t cnt;
 int error;
};

struct request_queue;

struct sg_iovec;

#define bvec_kmap_irq(bvec, flags) (page_address((bvec)->bv_page) + (bvec)->bv_offset)
#define bvec_kunmap_irq(buf, flags) do { *(flags) = 0; } while (0)

#define __bio_kunmap_irq(buf, flags) bvec_kunmap_irq(buf, flags)
#define bio_kmap_irq(bio, flags)   __bio_kmap_irq((bio), (bio)->bi_idx, (flags))
#define bio_kunmap_irq(buf,flags) __bio_kunmap_irq(buf, flags)
#endif
