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
#ifndef __HYPERCALL_H__
#define __HYPERCALL_H__

#include <linux/errno.h>
#include <linux/string.h>

#include <xen/interface/xen.h>
#include <xen/interface/sched.h>
#include <xen/interface/physdev.h>

#define _hypercall0(type, name)  ({   long __res;   asm volatile (   "call %[call]"   : "=a" (__res)   : [call] "m" (hypercall_page[__HYPERVISOR_##name])   : "memory" );   (type)__res;  })

#define _hypercall1(type, name, a1)  ({   long __res, __ign1;   asm volatile (   "call %[call]"   : "=a" (__res), "=b" (__ign1)   : "1" ((long)(a1)),   [call] "m" (hypercall_page[__HYPERVISOR_##name])   : "memory" );   (type)__res;  })

#define _hypercall2(type, name, a1, a2)  ({   long __res, __ign1, __ign2;   asm volatile (   "call %[call]"   : "=a" (__res), "=b" (__ign1), "=c" (__ign2)   : "1" ((long)(a1)), "2" ((long)(a2)),   [call] "m" (hypercall_page[__HYPERVISOR_##name])   : "memory" );   (type)__res;  })

#define _hypercall3(type, name, a1, a2, a3)  ({   long __res, __ign1, __ign2, __ign3;   asm volatile (   "call %[call]"   : "=a" (__res), "=b" (__ign1), "=c" (__ign2),   "=d" (__ign3)   : "1" ((long)(a1)), "2" ((long)(a2)),   "3" ((long)(a3)),   [call] "m" (hypercall_page[__HYPERVISOR_##name])   : "memory" );   (type)__res;  })

#define _hypercall4(type, name, a1, a2, a3, a4)  ({   long __res, __ign1, __ign2, __ign3, __ign4;   asm volatile (   "call %[call]"   : "=a" (__res), "=b" (__ign1), "=c" (__ign2),   "=d" (__ign3), "=S" (__ign4)   : "1" ((long)(a1)), "2" ((long)(a2)),   "3" ((long)(a3)), "4" ((long)(a4)),   [call] "m" (hypercall_page[__HYPERVISOR_##name])   : "memory" );   (type)__res;  })

#define _hypercall5(type, name, a1, a2, a3, a4, a5)  ({   long __res, __ign1, __ign2, __ign3, __ign4, __ign5;   asm volatile (   "call %[call]"   : "=a" (__res), "=b" (__ign1), "=c" (__ign2),   "=d" (__ign3), "=S" (__ign4), "=D" (__ign5)   : "1" ((long)(a1)), "2" ((long)(a2)),   "3" ((long)(a3)), "4" ((long)(a4)),   "5" ((long)(a5)),   [call] "m" (hypercall_page[__HYPERVISOR_##name])   : "memory" );   (type)__res;  })

#endif
