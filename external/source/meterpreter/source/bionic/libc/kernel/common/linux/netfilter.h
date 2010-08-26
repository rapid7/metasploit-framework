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
#ifndef __LINUX_NETFILTER_H
#define __LINUX_NETFILTER_H

#include <linux/compiler.h>

#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define NF_QUEUE 3
#define NF_REPEAT 4
#define NF_STOP 5
#define NF_MAX_VERDICT NF_STOP

#define NF_VERDICT_MASK 0x0000ffff
#define NF_VERDICT_BITS 16

#define NF_VERDICT_QMASK 0xffff0000
#define NF_VERDICT_QBITS 16

#define NF_QUEUE_NR(x) (((x << NF_VERDICT_QBITS) & NF_VERDICT_QMASK) | NF_QUEUE)

#define NFC_UNKNOWN 0x4000
#define NFC_ALTERED 0x8000

#endif
