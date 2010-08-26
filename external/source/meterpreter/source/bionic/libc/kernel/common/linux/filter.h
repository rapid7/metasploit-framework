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
#ifndef __LINUX_FILTER_H__
#define __LINUX_FILTER_H__

#include <linux/compiler.h>
#include <linux/types.h>

#define BPF_MAJOR_VERSION 1
#define BPF_MINOR_VERSION 1

struct sock_filter
{
 __u16 code;
 __u8 jt;
 __u8 jf;
 __u32 k;
};

struct sock_fprog
{
 unsigned short len;
 struct sock_filter __user *filter;
};

#define BPF_CLASS(code) ((code) & 0x07)
#define BPF_LD 0x00
#define BPF_LDX 0x01
#define BPF_ST 0x02
#define BPF_STX 0x03
#define BPF_ALU 0x04
#define BPF_JMP 0x05
#define BPF_RET 0x06
#define BPF_MISC 0x07

#define BPF_SIZE(code) ((code) & 0x18)
#define BPF_W 0x00
#define BPF_H 0x08
#define BPF_B 0x10
#define BPF_MODE(code) ((code) & 0xe0)
#define BPF_IMM 0x00
#define BPF_ABS 0x20
#define BPF_IND 0x40
#define BPF_MEM 0x60
#define BPF_LEN 0x80
#define BPF_MSH 0xa0

#define BPF_OP(code) ((code) & 0xf0)
#define BPF_ADD 0x00
#define BPF_SUB 0x10
#define BPF_MUL 0x20
#define BPF_DIV 0x30
#define BPF_OR 0x40
#define BPF_AND 0x50
#define BPF_LSH 0x60
#define BPF_RSH 0x70
#define BPF_NEG 0x80
#define BPF_JA 0x00
#define BPF_JEQ 0x10
#define BPF_JGT 0x20
#define BPF_JGE 0x30
#define BPF_JSET 0x40
#define BPF_SRC(code) ((code) & 0x08)
#define BPF_K 0x00
#define BPF_X 0x08

#define BPF_RVAL(code) ((code) & 0x18)
#define BPF_A 0x10

#define BPF_MISCOP(code) ((code) & 0xf8)
#define BPF_TAX 0x00
#define BPF_TXA 0x80

#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

#ifndef BPF_STMT
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#endif

#define BPF_MEMWORDS 16

#define SKF_AD_OFF (-0x1000)
#define SKF_AD_PROTOCOL 0
#define SKF_AD_PKTTYPE 4
#define SKF_AD_IFINDEX 8
#define SKF_AD_MAX 12
#define SKF_NET_OFF (-0x100000)
#define SKF_LL_OFF (-0x200000)

#endif
