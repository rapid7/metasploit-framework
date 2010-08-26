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
#ifndef _ASM_REQUIRED_FEATURES_H
#define _ASM_REQUIRED_FEATURES_H 1

#define NEED_FPU (1<<(X86_FEATURE_FPU & 31))

#define NEED_PAE 0
#define NEED_CX8 0

#define NEED_CMOV 0

#define NEED_3DNOW 0

#define NEED_PSE 0
#define NEED_MSR 0
#define NEED_PGE 0
#define NEED_FXSR 0
#define NEED_XMM 0
#define NEED_XMM2 0
#define NEED_LM 0

#define REQUIRED_MASK0 (NEED_FPU|NEED_PSE|NEED_MSR|NEED_PAE|  NEED_CX8|NEED_PGE|NEED_FXSR|NEED_CMOV|  NEED_XMM|NEED_XMM2)
#define SSE_MASK (NEED_XMM|NEED_XMM2)

#define REQUIRED_MASK1 (NEED_LM|NEED_3DNOW)

#define REQUIRED_MASK2 0
#define REQUIRED_MASK3 0
#define REQUIRED_MASK4 0
#define REQUIRED_MASK5 0
#define REQUIRED_MASK6 0
#define REQUIRED_MASK7 0

#endif
