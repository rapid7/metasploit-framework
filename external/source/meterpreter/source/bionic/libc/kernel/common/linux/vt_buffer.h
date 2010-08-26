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
#ifndef _LINUX_VT_BUFFER_H_
#define _LINUX_VT_BUFFER_H_

#ifndef VT_BUF_HAVE_RW
#define scr_writew(val, addr) (*(addr) = (val))
#define scr_readw(addr) (*(addr))
#define scr_memcpyw(d, s, c) memcpy(d, s, c)
#define scr_memmovew(d, s, c) memmove(d, s, c)
#define VT_BUF_HAVE_MEMCPYW
#define VT_BUF_HAVE_MEMMOVEW
#endif

#ifndef VT_BUF_HAVE_MEMSETW
#endif
#ifndef VT_BUF_HAVE_MEMCPYW
#endif
#ifndef VT_BUF_HAVE_MEMMOVEW
#endif
#endif
