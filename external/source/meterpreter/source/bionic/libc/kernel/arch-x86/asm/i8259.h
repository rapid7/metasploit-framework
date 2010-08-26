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
#ifndef __ASM_I8259_H__
#define __ASM_I8259_H__

#define __byte(x,y) (((unsigned char *) &(y))[x])
#define cached_master_mask (__byte(0, cached_irq_mask))
#define cached_slave_mask (__byte(1, cached_irq_mask))

#endif
