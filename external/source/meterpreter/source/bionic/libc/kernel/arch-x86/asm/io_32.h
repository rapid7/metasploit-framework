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
#ifndef _ASM_IO_H
#define _ASM_IO_H

#include <linux/string.h>
#include <linux/compiler.h>

#define IO_SPACE_LIMIT 0xffff

#define XQUAD_PORTIO_BASE 0xfe400000
#define XQUAD_PORTIO_QUAD 0x40000  

#ifdef REALLY_SLOW_IO
#endif
#define __BUILDIO(bwl,bw,type)  static inline void out##bwl(unsigned type value, int port) {   out##bwl##_local(value, port);  }  static inline unsigned type in##bwl(int port) {   return in##bwl##_local(port);  }
#define BUILDIO(bwl,bw,type)  static inline void out##bwl##_local(unsigned type value, int port) {   __asm__ __volatile__("out" #bwl " %" #bw "0, %w1" : : "a"(value), "Nd"(port));  }  static inline unsigned type in##bwl##_local(int port) {   unsigned type value;   __asm__ __volatile__("in" #bwl " %w1, %" #bw "0" : "=a"(value) : "Nd"(port));   return value;  }  static inline void out##bwl##_local_p(unsigned type value, int port) {   out##bwl##_local(value, port);   slow_down_io();  }  static inline unsigned type in##bwl##_local_p(int port) {   unsigned type value = in##bwl##_local(port);   slow_down_io();   return value;  }  __BUILDIO(bwl,bw,type)  static inline void out##bwl##_p(unsigned type value, int port) {   out##bwl(value, port);   slow_down_io();  }  static inline unsigned type in##bwl##_p(int port) {   unsigned type value = in##bwl(port);   slow_down_io();   return value;  }  static inline void outs##bwl(int port, const void *addr, unsigned long count) {   __asm__ __volatile__("rep; outs" #bwl : "+S"(addr), "+c"(count) : "d"(port));  }  static inline void ins##bwl(int port, void *addr, unsigned long count) {   __asm__ __volatile__("rep; ins" #bwl : "+D"(addr), "+c"(count) : "d"(port));  }
#endif
