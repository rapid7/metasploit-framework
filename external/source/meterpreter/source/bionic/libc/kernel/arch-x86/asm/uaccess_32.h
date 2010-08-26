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
#ifndef __i386_UACCESS_H
#define __i386_UACCESS_H

#include <linux/errno.h>
#include <linux/thread_info.h>
#include <linux/prefetch.h>
#include <linux/string.h>
#include <asm/page.h>

#define VERIFY_READ 0
#define VERIFY_WRITE 1

#define MAKE_MM_SEG(s) ((mm_segment_t) { (s) })

#define KERNEL_DS MAKE_MM_SEG(0xFFFFFFFFUL)
#define USER_DS MAKE_MM_SEG(PAGE_OFFSET)

#define get_ds() (KERNEL_DS)
#define get_fs() (current_thread_info()->addr_limit)
#define set_fs(x) (current_thread_info()->addr_limit = (x))

#define segment_eq(a,b) ((a).seg == (b).seg)

#define __addr_ok(addr) ((unsigned long __force)(addr) < (current_thread_info()->addr_limit.seg))

#define __range_ok(addr,size) ({   unsigned long flag,roksum;   __chk_user_ptr(addr);   asm("addl %3,%1 ; sbbl %0,%0; cmpl %1,%4; sbbl $0,%0"   :"=&r" (flag), "=r" (roksum)   :"1" (addr),"g" ((int)(size)),"rm" (current_thread_info()->addr_limit.seg));   flag; })

#define access_ok(type,addr,size) (likely(__range_ok(addr,size) == 0))

struct exception_table_entry
{
 unsigned long insn, fixup;
};

#define __get_user_x(size,ret,x,ptr)   __asm__ __volatile__("call __get_user_" #size   :"=a" (ret),"=d" (x)   :"0" (ptr))

#define get_user(x,ptr)  ({ int __ret_gu;   unsigned long __val_gu;   __chk_user_ptr(ptr);   switch(sizeof (*(ptr))) {   case 1: __get_user_x(1,__ret_gu,__val_gu,ptr); break;   case 2: __get_user_x(2,__ret_gu,__val_gu,ptr); break;   case 4: __get_user_x(4,__ret_gu,__val_gu,ptr); break;   default: __get_user_x(X,__ret_gu,__val_gu,ptr); break;   }   (x) = (__typeof__(*(ptr)))__val_gu;   __ret_gu;  })

#define __put_user_1(x, ptr) __asm__ __volatile__("call __put_user_1":"=a" (__ret_pu):"0" ((typeof(*(ptr)))(x)), "c" (ptr))
#define __put_user_2(x, ptr) __asm__ __volatile__("call __put_user_2":"=a" (__ret_pu):"0" ((typeof(*(ptr)))(x)), "c" (ptr))
#define __put_user_4(x, ptr) __asm__ __volatile__("call __put_user_4":"=a" (__ret_pu):"0" ((typeof(*(ptr)))(x)), "c" (ptr))
#define __put_user_8(x, ptr) __asm__ __volatile__("call __put_user_8":"=a" (__ret_pu):"A" ((typeof(*(ptr)))(x)), "c" (ptr))
#define __put_user_X(x, ptr) __asm__ __volatile__("call __put_user_X":"=a" (__ret_pu):"c" (ptr))

#define put_user(x,ptr)  ({   int __ret_pu;   __typeof__(*(ptr)) __pus_tmp = x;   __ret_pu=0;   if(unlikely(__copy_to_user_ll(ptr, &__pus_tmp,   sizeof(*(ptr))) != 0))   __ret_pu=-EFAULT;   __ret_pu;   })

#define __get_user(x,ptr)   __get_user_nocheck((x),(ptr),sizeof(*(ptr)))

#define __put_user(x,ptr)   __put_user_nocheck((__typeof__(*(ptr)))(x),(ptr),sizeof(*(ptr)))

#define __put_user_nocheck(x,ptr,size)  ({   long __pu_err;   __put_user_size((x),(ptr),(size),__pu_err,-EFAULT);   __pu_err;  })

#define __put_user_u64(x, addr, err)   __asm__ __volatile__(   "1:	movl %%eax,0(%2)\n"   "2:	movl %%edx,4(%2)\n"   "3:\n"   ".section .fixup,\"ax\"\n"   "4:	movl %3,%0\n"   "	jmp 3b\n"   ".previous\n"   ".section __ex_table,\"a\"\n"   "	.align 4\n"   "	.long 1b,4b\n"   "	.long 2b,4b\n"   ".previous"   : "=r"(err)   : "A" (x), "r" (addr), "i"(-EFAULT), "0"(err))

#define __put_user_size(x,ptr,size,retval,errret)  do {   __typeof__(*(ptr)) __pus_tmp = x;   retval = 0;     if(unlikely(__copy_to_user_ll(ptr, &__pus_tmp, size) != 0))   retval = errret;  } while (0)

struct __large_struct { unsigned long buf[100]; };
#define __m(x) (*(struct __large_struct __user *)(x))

#define __put_user_asm(x, addr, err, itype, rtype, ltype, errret)   __asm__ __volatile__(   "1:	mov"itype" %"rtype"1,%2\n"   "2:\n"   ".section .fixup,\"ax\"\n"   "3:	movl %3,%0\n"   "	jmp 2b\n"   ".previous\n"   ".section __ex_table,\"a\"\n"   "	.align 4\n"   "	.long 1b,3b\n"   ".previous"   : "=r"(err)   : ltype (x), "m"(__m(addr)), "i"(errret), "0"(err))

#define __get_user_nocheck(x,ptr,size)  ({   long __gu_err;   unsigned long __gu_val;   __get_user_size(__gu_val,(ptr),(size),__gu_err,-EFAULT);  (x) = (__typeof__(*(ptr)))__gu_val;   __gu_err;  })

#define __get_user_size(x,ptr,size,retval,errret)  do {   retval = 0;   __chk_user_ptr(ptr);   switch (size) {   case 1: __get_user_asm(x,ptr,retval,"b","b","=q",errret);break;   case 2: __get_user_asm(x,ptr,retval,"w","w","=r",errret);break;   case 4: __get_user_asm(x,ptr,retval,"l","","=r",errret);break;   default: (x) = __get_user_bad();   }  } while (0)

#define __get_user_asm(x, addr, err, itype, rtype, ltype, errret)   __asm__ __volatile__(   "1:	mov"itype" %2,%"rtype"1\n"   "2:\n"   ".section .fixup,\"ax\"\n"   "3:	movl %3,%0\n"   "	xor"itype" %"rtype"1,%"rtype"1\n"   "	jmp 2b\n"   ".previous\n"   ".section __ex_table,\"a\"\n"   "	.align 4\n"   "	.long 1b,3b\n"   ".previous"   : "=r"(err), ltype (x)   : "m"(__m(addr)), "i"(errret), "0"(err))

#define ARCH_HAS_NOCACHE_UACCESS

#define strlen_user(str) strnlen_user(str, LONG_MAX)

#endif
