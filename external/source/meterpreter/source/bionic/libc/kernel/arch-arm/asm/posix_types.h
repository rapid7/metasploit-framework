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
#ifndef __ARCH_ARM_POSIX_TYPES_H
#define __ARCH_ARM_POSIX_TYPES_H

typedef unsigned long __kernel_ino_t;
typedef unsigned short __kernel_mode_t;
typedef unsigned short __kernel_nlink_t;
typedef long __kernel_off_t;
typedef int __kernel_pid_t;
typedef unsigned short __kernel_ipc_pid_t;
typedef unsigned short __kernel_uid_t;
typedef unsigned short __kernel_gid_t;
typedef unsigned int __kernel_size_t;
typedef int __kernel_ssize_t;
typedef int __kernel_ptrdiff_t;
typedef long __kernel_time_t;
typedef long __kernel_suseconds_t;
typedef long __kernel_clock_t;
typedef int __kernel_timer_t;
typedef int __kernel_clockid_t;
typedef int __kernel_daddr_t;
typedef char * __kernel_caddr_t;
typedef unsigned short __kernel_uid16_t;
typedef unsigned short __kernel_gid16_t;
typedef unsigned int __kernel_uid32_t;
typedef unsigned int __kernel_gid32_t;

typedef unsigned short __kernel_old_uid_t;
typedef unsigned short __kernel_old_gid_t;
typedef unsigned short __kernel_old_dev_t;

#ifdef __GNUC__
typedef long long __kernel_loff_t;
#endif

typedef struct {
#ifdef __USE_ALL
 int val[2];
#else
 int __val[2];
#endif
} __kernel_fsid_t;

#if !defined(__GLIBC__) || __GLIBC__ < 2

#undef __FD_SET
#define __FD_SET(fd, fdsetp)   (((fd_set *)(fdsetp))->fds_bits[(fd) >> 5] |= (1<<((fd) & 31)))

#undef __FD_CLR
#define __FD_CLR(fd, fdsetp)   (((fd_set *)(fdsetp))->fds_bits[(fd) >> 5] &= ~(1<<((fd) & 31)))

#undef __FD_ISSET
#define __FD_ISSET(fd, fdsetp)   ((((fd_set *)(fdsetp))->fds_bits[(fd) >> 5] & (1<<((fd) & 31))) != 0)

#undef __FD_ZERO
#define __FD_ZERO(fdsetp)   (memset (fdsetp, 0, sizeof (*(fd_set *)(fdsetp))))

#endif

#endif
