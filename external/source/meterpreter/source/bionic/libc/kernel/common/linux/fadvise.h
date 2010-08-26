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
#ifndef FADVISE_H_INCLUDED
#define FADVISE_H_INCLUDED

#define POSIX_FADV_NORMAL 0  
#define POSIX_FADV_RANDOM 1  
#define POSIX_FADV_SEQUENTIAL 2  
#define POSIX_FADV_WILLNEED 3  

#ifdef __s390x__
#define POSIX_FADV_DONTNEED 6  
#define POSIX_FADV_NOREUSE 7  
#else
#define POSIX_FADV_DONTNEED 4  
#define POSIX_FADV_NOREUSE 5  
#endif

#endif
