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
#ifndef __ASM_SH_PROCESSOR_H
#define __ASM_SH_PROCESSOR_H

#include <asm/cpu-features.h>
#include <asm/segment.h>

#ifndef __ASSEMBLY__

enum cpu_type {

 CPU_SH7619,

 CPU_SH7203, CPU_SH7206, CPU_SH7263, CPU_MXG,

 CPU_SH7705, CPU_SH7706, CPU_SH7707,
 CPU_SH7708, CPU_SH7708S, CPU_SH7708R,
 CPU_SH7709, CPU_SH7709A, CPU_SH7710, CPU_SH7712,
 CPU_SH7720, CPU_SH7721, CPU_SH7729,

 CPU_SH7750, CPU_SH7750S, CPU_SH7750R, CPU_SH7751, CPU_SH7751R,
 CPU_SH7760, CPU_SH4_202, CPU_SH4_501,

 CPU_SH7763, CPU_SH7770, CPU_SH7780, CPU_SH7781, CPU_SH7785,
 CPU_SH7723, CPU_SHX3,

 CPU_SH7343, CPU_SH7722, CPU_SH7366,

 CPU_SH5_101, CPU_SH5_103,

 CPU_SH_NONE
};

struct sh_cpuinfo;

#endif

#include "processor_32.h"

#endif
