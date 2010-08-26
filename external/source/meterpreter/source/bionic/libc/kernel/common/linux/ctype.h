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
#ifndef _LINUX_CTYPE_H
#define _LINUX_CTYPE_H

#define _U 0x01  
#define _L 0x02  
#define _D 0x04  
#define _C 0x08  
#define _P 0x10  
#define _S 0x20  
#define _X 0x40  
#define _SP 0x80  

#define __ismask(x) (_ctype[(int)(unsigned char)(x)])

#define isalnum(c) ((__ismask(c)&(_U|_L|_D)) != 0)
#define isalpha(c) ((__ismask(c)&(_U|_L)) != 0)
#define iscntrl(c) ((__ismask(c)&(_C)) != 0)
#define isdigit(c) ((__ismask(c)&(_D)) != 0)
#define isgraph(c) ((__ismask(c)&(_P|_U|_L|_D)) != 0)
#define islower(c) ((__ismask(c)&(_L)) != 0)
#define isprint(c) ((__ismask(c)&(_P|_U|_L|_D|_SP)) != 0)
#define ispunct(c) ((__ismask(c)&(_P)) != 0)
#define isspace(c) ((__ismask(c)&(_S)) != 0)
#define isupper(c) ((__ismask(c)&(_U)) != 0)
#define isxdigit(c) ((__ismask(c)&(_D|_X)) != 0)

#define isascii(c) (((unsigned char)(c))<=0x7f)
#define toascii(c) (((unsigned char)(c))&0x7f)

#define tolower(c) __tolower(c)
#define toupper(c) __toupper(c)
#endif
