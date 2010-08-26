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
#ifndef __ASM_ARM_FPSTATE_H
#define __ASM_ARM_FPSTATE_H

#ifndef __ASSEMBLY__

struct vfp_hard_struct {
 __u64 fpregs[16];
#if __LINUX_ARM_ARCH__ < 6
 __u32 fpmx_state;
#endif
 __u32 fpexc;
 __u32 fpscr;

 __u32 fpinst;
 __u32 fpinst2;
};

union vfp_state {
 struct vfp_hard_struct hard;
};

#define FP_HARD_SIZE 35

struct fp_hard_struct {
 unsigned int save[FP_HARD_SIZE];
};

#define FP_SOFT_SIZE 35

struct fp_soft_struct {
 unsigned int save[FP_SOFT_SIZE];
};

#define IWMMXT_SIZE 0x98

struct iwmmxt_struct {
 unsigned int save[IWMMXT_SIZE / sizeof(unsigned int)];
};

union fp_state {
 struct fp_hard_struct hard;
 struct fp_soft_struct soft;
};

#define FP_SIZE (sizeof(union fp_state) / sizeof(int))

struct crunch_state {
 unsigned int mvdx[16][2];
 unsigned int mvax[4][3];
 unsigned int dspsc[2];
};

#define CRUNCH_SIZE sizeof(struct crunch_state)

#endif

#endif
