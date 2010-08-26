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
#ifndef __ASM_MPSPEC_H
#define __ASM_MPSPEC_H

#include <linux/cpumask.h>
#include <asm/mpspec_def.h>
#include <mach_mpspec.h>

#define PHYSID_ARRAY_SIZE BITS_TO_LONGS(MAX_APICS)

struct physid_mask
{
 unsigned long mask[PHYSID_ARRAY_SIZE];
};

typedef struct physid_mask physid_mask_t;

#define physid_set(physid, map) set_bit(physid, (map).mask)
#define physid_clear(physid, map) clear_bit(physid, (map).mask)
#define physid_isset(physid, map) test_bit(physid, (map).mask)
#define physid_test_and_set(physid, map) test_and_set_bit(physid, (map).mask)

#define physids_and(dst, src1, src2) bitmap_and((dst).mask, (src1).mask, (src2).mask, MAX_APICS)
#define physids_or(dst, src1, src2) bitmap_or((dst).mask, (src1).mask, (src2).mask, MAX_APICS)
#define physids_clear(map) bitmap_zero((map).mask, MAX_APICS)
#define physids_complement(dst, src) bitmap_complement((dst).mask,(src).mask, MAX_APICS)
#define physids_empty(map) bitmap_empty((map).mask, MAX_APICS)
#define physids_equal(map1, map2) bitmap_equal((map1).mask, (map2).mask, MAX_APICS)
#define physids_weight(map) bitmap_weight((map).mask, MAX_APICS)
#define physids_shift_right(d, s, n) bitmap_shift_right((d).mask, (s).mask, n, MAX_APICS)
#define physids_shift_left(d, s, n) bitmap_shift_left((d).mask, (s).mask, n, MAX_APICS)
#define physids_coerce(map) ((map).mask[0])

#define physids_promote(physids)   ({   physid_mask_t __physid_mask = PHYSID_MASK_NONE;   __physid_mask.mask[0] = physids;   __physid_mask;   })

#define physid_mask_of_physid(physid)   ({   physid_mask_t __physid_mask = PHYSID_MASK_NONE;   physid_set(physid, __physid_mask);   __physid_mask;   })

#define PHYSID_MASK_ALL { {[0 ... PHYSID_ARRAY_SIZE-1] = ~0UL} }
#define PHYSID_MASK_NONE { {[0 ... PHYSID_ARRAY_SIZE-1] = 0UL} }

#endif

