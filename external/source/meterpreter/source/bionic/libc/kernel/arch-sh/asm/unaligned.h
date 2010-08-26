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
#ifndef _ASM_SH_UNALIGNED_H
#define _ASM_SH_UNALIGNED_H

#ifdef __LITTLE_ENDIAN__
#include <linux/unaligned/le_struct.h>
#include <linux/unaligned/be_byteshift.h>
#include <linux/unaligned/generic.h>
#define get_unaligned __get_unaligned_le
#define put_unaligned __put_unaligned_le
#else
#include <linux/unaligned/be_struct.h>
#include <linux/unaligned/le_byteshift.h>
#include <linux/unaligned/generic.h>
#define get_unaligned __get_unaligned_be
#define put_unaligned __put_unaligned_be
#endif

#endif
