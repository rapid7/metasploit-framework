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
#ifndef __ASM_SH_SEGMENT_H
#define __ASM_SH_SEGMENT_H

#ifndef __ASSEMBLY__

typedef struct {
 unsigned long seg;
} mm_segment_t;

#define MAKE_MM_SEG(s) ((mm_segment_t) { (s) })

#define KERNEL_DS MAKE_MM_SEG(0xFFFFFFFFUL)
#define USER_DS MAKE_MM_SEG(PAGE_OFFSET)

#define segment_eq(a,b) ((a).seg == (b).seg)

#define get_ds() (KERNEL_DS)

#define get_fs() (current_thread_info()->addr_limit)
#define set_fs(x) (current_thread_info()->addr_limit = (x))

#endif
#endif
