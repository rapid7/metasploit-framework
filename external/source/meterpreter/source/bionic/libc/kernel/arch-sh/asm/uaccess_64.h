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
#ifndef __ASM_SH_UACCESS_64_H
#define __ASM_SH_UACCESS_64_H

#define __get_user_size(x,ptr,size,retval)  do {   retval = 0;   switch (size) {   case 1:   retval = __get_user_asm_b(x, ptr);   break;   case 2:   retval = __get_user_asm_w(x, ptr);   break;   case 4:   retval = __get_user_asm_l(x, ptr);   break;   case 8:   retval = __get_user_asm_q(x, ptr);   break;   default:   __get_user_unknown();   break;   }  } while (0)

#define __put_user_size(x,ptr,size,retval)  do {   retval = 0;   switch (size) {   case 1:   retval = __put_user_asm_b(x, ptr);   break;   case 2:   retval = __put_user_asm_w(x, ptr);   break;   case 4:   retval = __put_user_asm_l(x, ptr);   break;   case 8:   retval = __put_user_asm_q(x, ptr);   break;   default:   __put_user_unknown();   }  } while (0)

#endif
