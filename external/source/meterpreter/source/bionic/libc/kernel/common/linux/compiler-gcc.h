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
#define barrier() __asm__ __volatile__("": : :"memory")

#define RELOC_HIDE(ptr, off)   ({ unsigned long __ptr;   __asm__ ("" : "=r"(__ptr) : "0"(ptr));   (typeof(ptr)) (__ptr + (off)); })

#define inline inline __attribute__((always_inline))
#define __inline__ __inline__ __attribute__((always_inline))
#define __inline __inline __attribute__((always_inline))
#define __deprecated __attribute__((deprecated))
#define noinline __attribute__((noinline))
#define __attribute_pure__ __attribute__((pure))
#define __attribute_const__ __attribute__((__const__))
