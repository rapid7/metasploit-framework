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
#ifndef _ASMARM_UACCESS_H
#define _ASMARM_UACCESS_H

#include <linux/sched.h>
#include <asm/errno.h>
#include <asm/memory.h>
#include <asm/domain.h>
#include <asm/system.h>

#define VERIFY_READ 0
#define VERIFY_WRITE 1

struct exception_table_entry
{
 unsigned long insn, fixup;
};

#define KERNEL_DS 0x00000000
#define get_ds() (KERNEL_DS)

#define USER_DS KERNEL_DS

#define segment_eq(a,b) (1)
#define __addr_ok(addr) (1)
#define __range_ok(addr,size) (0)
#define get_fs() (KERNEL_DS)

#define get_user(x,p) __get_user(x,p)
#define put_user(x,p) __put_user(x,p)
#define access_ok(type,addr,size) (__range_ok(addr,size) == 0)
#define __get_user(x,ptr)  ({   long __gu_err = 0;   __get_user_err((x),(ptr),__gu_err);   __gu_err;  })
#define __get_user_error(x,ptr,err)  ({   __get_user_err((x),(ptr),err);   (void) 0;  })
#define __get_user_err(x,ptr,err)  do {   unsigned long __gu_addr = (unsigned long)(ptr);   unsigned long __gu_val;   __chk_user_ptr(ptr);   switch (sizeof(*(ptr))) {   case 1: __get_user_asm_byte(__gu_val,__gu_addr,err); break;   case 2: __get_user_asm_half(__gu_val,__gu_addr,err); break;   case 4: __get_user_asm_word(__gu_val,__gu_addr,err); break;   default: (__gu_val) = __get_user_bad();   }   (x) = (__typeof__(*(ptr)))__gu_val;  } while (0)
#define __get_user_asm_byte(x,addr,err)   __asm__ __volatile__(   "1:	ldrbt	%1,[%2],#0\n"   "2:\n"   "	.section .fixup,\"ax\"\n"   "	.align	2\n"   "3:	mov	%0, %3\n"   "	mov	%1, #0\n"   "	b	2b\n"   "	.previous\n"   "	.section __ex_table,\"a\"\n"   "	.align	3\n"   "	.long	1b, 3b\n"   "	.previous"   : "+r" (err), "=&r" (x)   : "r" (addr), "i" (-EFAULT)   : "cc")
#ifndef __ARMEB__
#define __get_user_asm_half(x,__gu_addr,err)  ({   unsigned long __b1, __b2;   __get_user_asm_byte(__b1, __gu_addr, err);   __get_user_asm_byte(__b2, __gu_addr + 1, err);   (x) = __b1 | (__b2 << 8);  })
#else
#define __get_user_asm_half(x,__gu_addr,err)  ({   unsigned long __b1, __b2;   __get_user_asm_byte(__b1, __gu_addr, err);   __get_user_asm_byte(__b2, __gu_addr + 1, err);   (x) = (__b1 << 8) | __b2;  })
#endif
#define __get_user_asm_word(x,addr,err)   __asm__ __volatile__(   "1:	ldrt	%1,[%2],#0\n"   "2:\n"   "	.section .fixup,\"ax\"\n"   "	.align	2\n"   "3:	mov	%0, %3\n"   "	mov	%1, #0\n"   "	b	2b\n"   "	.previous\n"   "	.section __ex_table,\"a\"\n"   "	.align	3\n"   "	.long	1b, 3b\n"   "	.previous"   : "+r" (err), "=&r" (x)   : "r" (addr), "i" (-EFAULT)   : "cc")
#define __put_user(x,ptr)  ({   long __pu_err = 0;   __put_user_err((x),(ptr),__pu_err);   __pu_err;  })
#define __put_user_error(x,ptr,err)  ({   __put_user_err((x),(ptr),err);   (void) 0;  })
#define __put_user_err(x,ptr,err)  do {   unsigned long __pu_addr = (unsigned long)(ptr);   __typeof__(*(ptr)) __pu_val = (x);   __chk_user_ptr(ptr);   switch (sizeof(*(ptr))) {   case 1: __put_user_asm_byte(__pu_val,__pu_addr,err); break;   case 2: __put_user_asm_half(__pu_val,__pu_addr,err); break;   case 4: __put_user_asm_word(__pu_val,__pu_addr,err); break;   case 8: __put_user_asm_dword(__pu_val,__pu_addr,err); break;   default: __put_user_bad();   }  } while (0)
#define __put_user_asm_byte(x,__pu_addr,err)   __asm__ __volatile__(   "1:	strbt	%1,[%2],#0\n"   "2:\n"   "	.section .fixup,\"ax\"\n"   "	.align	2\n"   "3:	mov	%0, %3\n"   "	b	2b\n"   "	.previous\n"   "	.section __ex_table,\"a\"\n"   "	.align	3\n"   "	.long	1b, 3b\n"   "	.previous"   : "+r" (err)   : "r" (x), "r" (__pu_addr), "i" (-EFAULT)   : "cc")
#ifndef __ARMEB__
#define __put_user_asm_half(x,__pu_addr,err)  ({   unsigned long __temp = (unsigned long)(x);   __put_user_asm_byte(__temp, __pu_addr, err);   __put_user_asm_byte(__temp >> 8, __pu_addr + 1, err);  })
#else
#define __put_user_asm_half(x,__pu_addr,err)  ({   unsigned long __temp = (unsigned long)(x);   __put_user_asm_byte(__temp >> 8, __pu_addr, err);   __put_user_asm_byte(__temp, __pu_addr + 1, err);  })
#endif
#define __put_user_asm_word(x,__pu_addr,err)   __asm__ __volatile__(   "1:	strt	%1,[%2],#0\n"   "2:\n"   "	.section .fixup,\"ax\"\n"   "	.align	2\n"   "3:	mov	%0, %3\n"   "	b	2b\n"   "	.previous\n"   "	.section __ex_table,\"a\"\n"   "	.align	3\n"   "	.long	1b, 3b\n"   "	.previous"   : "+r" (err)   : "r" (x), "r" (__pu_addr), "i" (-EFAULT)   : "cc")
#ifndef __ARMEB__
#define __reg_oper0 "%R2"
#define __reg_oper1 "%Q2"
#else
#define __reg_oper0 "%Q2"
#define __reg_oper1 "%R2"
#endif
#define __put_user_asm_dword(x,__pu_addr,err)   __asm__ __volatile__(   "1:	strt	" __reg_oper1 ", [%1], #4\n"   "2:	strt	" __reg_oper0 ", [%1], #0\n"   "3:\n"   "	.section .fixup,\"ax\"\n"   "	.align	2\n"   "4:	mov	%0, %3\n"   "	b	3b\n"   "	.previous\n"   "	.section __ex_table,\"a\"\n"   "	.align	3\n"   "	.long	1b, 4b\n"   "	.long	2b, 4b\n"   "	.previous"   : "+r" (err), "+r" (__pu_addr)   : "r" (x), "i" (-EFAULT)   : "cc")
#define __copy_from_user(to,from,n) (memcpy(to, (void __force *)from, n), 0)
#define __copy_to_user(to,from,n) (memcpy((void __force *)to, from, n), 0)
#define __clear_user(addr,n) (memset((void __force *)addr, 0, n), 0)

#define __copy_to_user_inatomic __copy_to_user
#define __copy_from_user_inatomic __copy_from_user
#define strlen_user(s) strnlen_user(s, ~0UL >> 1)
#endif
