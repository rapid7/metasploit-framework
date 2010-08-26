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
#ifndef __ARCH_I386_PERCPU__
#define __ARCH_I386_PERCPU__

#ifdef __ASSEMBLY__

#define PER_CPU(var, reg)   movl $per_cpu__##var, reg
#define PER_CPU_VAR(var) per_cpu__##var

#else

#include <asm-generic/percpu.h>
#define __percpu_seg ""

#define percpu_to_op(op,var,val)   do {   typedef typeof(var) T__;   if (0) { T__ tmp__; tmp__ = (val); }   switch (sizeof(var)) {   case 1:   asm(op "b %1,"__percpu_seg"%0"   : "+m" (var)   :"ri" ((T__)val));   break;   case 2:   asm(op "w %1,"__percpu_seg"%0"   : "+m" (var)   :"ri" ((T__)val));   break;   case 4:   asm(op "l %1,"__percpu_seg"%0"   : "+m" (var)   :"ri" ((T__)val));   break;   default: __bad_percpu_size();   }   } while (0)

#define percpu_from_op(op,var)   ({   typeof(var) ret__;   switch (sizeof(var)) {   case 1:   asm(op "b "__percpu_seg"%1,%0"   : "=r" (ret__)   : "m" (var));   break;   case 2:   asm(op "w "__percpu_seg"%1,%0"   : "=r" (ret__)   : "m" (var));   break;   case 4:   asm(op "l "__percpu_seg"%1,%0"   : "=r" (ret__)   : "m" (var));   break;   default: __bad_percpu_size();   }   ret__; })

#define x86_read_percpu(var) percpu_from_op("mov", per_cpu__##var)
#define x86_write_percpu(var,val) percpu_to_op("mov", per_cpu__##var, val)
#define x86_add_percpu(var,val) percpu_to_op("add", per_cpu__##var, val)
#define x86_sub_percpu(var,val) percpu_to_op("sub", per_cpu__##var, val)
#define x86_or_percpu(var,val) percpu_to_op("or", per_cpu__##var, val)
#endif

#endif
