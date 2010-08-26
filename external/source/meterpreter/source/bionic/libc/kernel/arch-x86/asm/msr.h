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
#ifndef __ASM_X86_MSR_H_
#define __ASM_X86_MSR_H_

#include <asm/msr-index.h>

#ifndef __ASSEMBLY__
#include <linux/types.h>
#endif

#ifdef __i386__

#else

#ifndef __ASSEMBLY__
#include <linux/errno.h>

#define rdmsr(msr,val1,val2)   __asm__ __volatile__("rdmsr"   : "=a" (val1), "=d" (val2)   : "c" (msr))

#define rdmsrl(msr,val) do { unsigned long a__,b__;   __asm__ __volatile__("rdmsr"   : "=a" (a__), "=d" (b__)   : "c" (msr));   val = a__ | (b__<<32);  } while(0)

#define wrmsr(msr,val1,val2)   __asm__ __volatile__("wrmsr"   :     : "c" (msr), "a" (val1), "d" (val2))

#define wrmsrl(msr,val) wrmsr(msr,(__u32)((__u64)(val)),((__u64)(val))>>32)

#define rdtsc(low,high)   __asm__ __volatile__("rdtsc" : "=a" (low), "=d" (high))

#define rdtscl(low)   __asm__ __volatile__ ("rdtsc" : "=a" (low) : : "edx")

#define rdtscp(low,high,aux)   __asm__ __volatile__ (".byte 0x0f,0x01,0xf9" : "=a" (low), "=d" (high), "=c" (aux))

#define rdtscll(val) do {   unsigned int __a,__d;   __asm__ __volatile__("rdtsc" : "=a" (__a), "=d" (__d));   (val) = ((unsigned long)__a) | (((unsigned long)__d)<<32);  } while(0)

#define rdtscpll(val, aux) do {   unsigned long __a, __d;   __asm__ __volatile__ (".byte 0x0f,0x01,0xf9" : "=a" (__a), "=d" (__d), "=c" (aux));   (val) = (__d << 32) | __a;  } while (0)

#define write_tsc(val1,val2) wrmsr(0x10, val1, val2)

#define write_rdtscp_aux(val) wrmsr(0xc0000103, val, 0)

#define rdpmc(counter,low,high)   __asm__ __volatile__("rdpmc"   : "=a" (low), "=d" (high)   : "c" (counter))

#endif
#endif
#endif
