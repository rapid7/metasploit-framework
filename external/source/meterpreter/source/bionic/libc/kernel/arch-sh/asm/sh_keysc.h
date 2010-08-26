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
#ifndef __ASM_KEYSC_H__
#define __ASM_KEYSC_H__

#define SH_KEYSC_MAXKEYS 30

struct sh_keysc_info {
 enum { SH_KEYSC_MODE_1, SH_KEYSC_MODE_2, SH_KEYSC_MODE_3 } mode;
 int scan_timing;
 int delay;
 int keycodes[SH_KEYSC_MAXKEYS];
};

#endif
