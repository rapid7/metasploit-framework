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
#ifndef __ASM_SH_UACCESS_H
#define __ASM_SH_UACCESS_H

#include <linux/errno.h>
#include <linux/sched.h>
#include <asm/segment.h>

#define VERIFY_READ 0
#define VERIFY_WRITE 1

#define __addr_ok(addr)   ((unsigned long __force)(addr) < current_thread_info()->addr_limit.seg)

#define __access_ok(addr, size)   (__addr_ok((addr) + (size)))
#define access_ok(type, addr, size)   (__chk_user_ptr(addr),   __access_ok((unsigned long __force)(addr), (size)))

#define put_user(x,ptr) __put_user_check((x), (ptr), sizeof(*(ptr)))
#define get_user(x,ptr) __get_user_check((x), (ptr), sizeof(*(ptr)))

#define __put_user(x,ptr) __put_user_nocheck((x), (ptr), sizeof(*(ptr)))
#define __get_user(x,ptr) __get_user_nocheck((x), (ptr), sizeof(*(ptr)))

struct __large_struct { unsigned long buf[100]; };
#define __m(x) (*(struct __large_struct __user *)(x))

#define __get_user_nocheck(x,ptr,size)  ({   long __gu_err;   unsigned long __gu_val;   const __typeof__(*(ptr)) __user *__gu_addr = (ptr);   __chk_user_ptr(ptr);   __get_user_size(__gu_val, __gu_addr, (size), __gu_err);   (x) = (__typeof__(*(ptr)))__gu_val;   __gu_err;  })

#define __get_user_check(x,ptr,size)  ({   long __gu_err = -EFAULT;   unsigned long __gu_val = 0;   const __typeof__(*(ptr)) *__gu_addr = (ptr);   if (likely(access_ok(VERIFY_READ, __gu_addr, (size))))   __get_user_size(__gu_val, __gu_addr, (size), __gu_err);   (x) = (__typeof__(*(ptr)))__gu_val;   __gu_err;  })

#define __put_user_nocheck(x,ptr,size)  ({   long __pu_err;   __typeof__(*(ptr)) __user *__pu_addr = (ptr);   __typeof__(*(ptr)) __pu_val = x;   __chk_user_ptr(ptr);   __put_user_size(__pu_val, __pu_addr, (size), __pu_err);   __pu_err;  })

#define __put_user_check(x,ptr,size)  ({   long __pu_err = -EFAULT;   __typeof__(*(ptr)) __user *__pu_addr = (ptr);   __typeof__(*(ptr)) __pu_val = x;   if (likely(access_ok(VERIFY_WRITE, __pu_addr, size)))   __put_user_size(__pu_val, __pu_addr, (size),   __pu_err);   __pu_err;  })

#include "uaccess_32.h"

#define __copy_to_user_inatomic __copy_to_user
#define __copy_from_user_inatomic __copy_from_user

#define clear_user(addr,n)  ({   void __user * __cl_addr = (addr);   unsigned long __cl_size = (n);     if (__cl_size && access_ok(VERIFY_WRITE,   ((unsigned long)(__cl_addr)), __cl_size))   __cl_size = __clear_user(__cl_addr, __cl_size);     __cl_size;  })

#define strncpy_from_user(dest,src,count)  ({   unsigned long __sfu_src = (unsigned long)(src);   int __sfu_count = (int)(count);   long __sfu_res = -EFAULT;     if (__access_ok(__sfu_src, __sfu_count))   __sfu_res = __strncpy_from_user((unsigned long)(dest),   __sfu_src, __sfu_count);     __sfu_res;  })

#define strlen_user(str) strnlen_user(str, ~0UL >> 1)

#endif
