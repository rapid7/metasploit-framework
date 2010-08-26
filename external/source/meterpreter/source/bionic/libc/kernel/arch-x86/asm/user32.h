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
#ifndef USER32_H
#define USER32_H 1

struct user_i387_ia32_struct {
 u32 cwd;
 u32 swd;
 u32 twd;
 u32 fip;
 u32 fcs;
 u32 foo;
 u32 fos;
 u32 st_space[20];
};

struct user32_fxsr_struct {
 unsigned short cwd;
 unsigned short swd;
 unsigned short twd;
 unsigned short fop;
 int fip;
 int fcs;
 int foo;
 int fos;
 int mxcsr;
 int reserved;
 int st_space[32];
 int xmm_space[32];
 int padding[56];
};

struct user_regs_struct32 {
 __u32 ebx, ecx, edx, esi, edi, ebp, eax;
 unsigned short ds, __ds, es, __es;
 unsigned short fs, __fs, gs, __gs;
 __u32 orig_eax, eip;
 unsigned short cs, __cs;
 __u32 eflags, esp;
 unsigned short ss, __ss;
};

struct user32 {
 struct user_regs_struct32 regs;
 int u_fpvalid;

 struct user_i387_ia32_struct i387;

 __u32 u_tsize;
 __u32 u_dsize;
 __u32 u_ssize;
 __u32 start_code;
 __u32 start_stack;
 __u32 signal;
 int reserved;
 __u32 u_ar0;

 __u32 u_fpstate;
 __u32 magic;
 char u_comm[32];
 int u_debugreg[8];
};

#endif
