/*
 * derived from:
 * 
 * sfsyscall.h -- shellforge syscall implementation
 *                see http://www.cartel-securite.net/pbiondi/shellforge.html
 *                for more informations
 *
 * Copyright (C) 2003  Philippe Biondi <biondi@cartel-securite.fr>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

/* $Id: sfsyscall.h,v 1.5 2003/08/25 14:30:33 pbi Exp $ */

/* Remove errno stuff */
#include <sys/syscall.h>



#define __sfsyscall_return(type, res)		\
do { \
	return (type) (res); \
} while (0)

/* XXX - _foo needs to be __foo, while __NR_bar could be _NR_bar. */
#define _sfsyscall0(type,name) \
type name(void) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_##name)); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall1(type,name,type1,arg1) \
type name(type1 arg1) \
{ \
long __res; \
__asm__ volatile ("pushl %%ebx\n\t"     \
                  "mov %2,%%ebx\n\t"    \
		  "int $0x80\n\t"       \
                  "popl %%ebx"          \
	: "=a" (__res) \
	: "0" (__NR_##name),"g" ((long)(arg1))); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall2(type,name,type1,arg1,type2,arg2) \
type name(type1 arg1,type2 arg2) \
{ \
long __res; \
__asm__ volatile ("pushl %%ebx\n\t"     \
                  "mov %2,%%ebx\n\t"    \
		  "int $0x80\n\t"       \
                  "popl %%ebx"          \
	: "=a" (__res) \
	: "0" (__NR_##name),"g" ((long)(arg1)),"c" ((long)(arg2)) ); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ volatile ("pushl %%ebx\n\t"     \
                  "mov %2,%%ebx\n\t"    \
		  "int $0x80\n\t"       \
                  "popl %%ebx"          \
	: "=a" (__res) \
	: "0" (__NR_##name),"g" ((long)(arg1)),"c" ((long)(arg2)), \
		  "d" ((long)(arg3)) ); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
long __res; \
__asm__ volatile ("pushl %%ebx\n\t"     \
                  "mov %2,%%ebx\n\t"    \
		  "int $0x80\n\t"       \
                  "popl %%ebx"          \
	: "=a" (__res) \
	: "0" (__NR_##name),"g" ((long)(arg1)),"c" ((long)(arg2)), \
	  "d" ((long)(arg3)),"S" ((long)(arg4)) ); \
__sfsyscall_return(type,__res); \
} 

#define _sfsyscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{ \
long __res; \
__asm__ volatile ("pushl %%ebx\n\t"     \
                  "mov %2,%%ebx\n\t"    \
		  "int $0x80\n\t"       \
                  "popl %%ebx"          \
	: "=a" (__res) \
	: "0" (__NR_##name),"g" ((long)(arg1)),"c" ((long)(arg2)), \
	  "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5))); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5,type6,arg6) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5, type6 arg6) \
{ \
long __res; \
__asm__ volatile ("pushl %%ebx\n\t"  \
		  "pushl %%ebp\n\t"  \
                  "movl %2,%%ebx\n\t" \
                  "movl %7,%%ebp\n\t" \
		  "int $0x80\n\t"    \
		  "popl %%ebp\n\t"   \
                  "popl %%ebx"       \
	: "=a" (__res) \
	: "0" (__NR_##name),"g" ((long)(arg1)),"c" ((long)(arg2)), \
	  "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5)), \
	  "g" ((long)(arg6))); \
__sfsyscall_return(type,__res); \
}


#define _sfoldsyscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
          type5,arg5,type6,arg6) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5, type6 arg6) \
{ \
long __res; \
__asm__ volatile ("pushl %%ebx\n\t"  \
                  "pushl %7\n\t" \
                  "pushl %6\n\t" \
                  "pushl %5\n\t" \
                  "pushl %4\n\t" \
                  "pushl %3\n\t" \
                  "pushl %2\n\t" \
                  "movl %%esp, %%ebx\n\t" \
                  "int $0x80\n\t"    \
                  "add $0x18,%%esp\n\t"  \
                  "popl %%ebx"   \
        : "=a" (__res) \
        : "0" (__NR_##name),"g" ((long)(arg1)),"g" ((long)(arg2)), \
          "g" ((long)(arg3)),"g" ((long)(arg4)),"g" ((long)(arg5)), \
          "g" ((long)(arg6))); \
__sfsyscall_return(type,__res); \
}


#if 0

#endif

/****
_sfsyscall3(int, read, int, fd, void *, buf, long, count)
_sfsyscall3(int, write, int, fd, void *, buf, long, count)
_sfsyscall3(int, execve, char *, s, char **, argv, char **,envp)
_sfsyscall1(int, close, int, fd)
_sfsyscall3(int, open, char *, path, int, mode, int, flags)



static inline _sfsyscall2(int, setreuid, int, reuid, int, euid)
static inline _sfsyscall1(int, chroot, char *,path)
static inline _sfsyscall1(int, dup, int, fd)

static inline _sfsyscall2(int, dup2, int, ofd, int, nfd)

static inline _sfsyscall1(int, chdir, char *, path)
static inline _sfsyscall3(int, chown, char *, path, int, uid, int, gid)
static inline _sfsyscall2(int, chmod, char *, path, int, mode)
static inline _sfsyscall0(int, fork)

static inline _sfsyscall0(int, getuid)
static inline _sfsyscall0(int, geteuid)
static inline _sfsyscall2(int, socketcall, int, call, unsigned long *,args)
static inline _sfsyscall4(int, ioctl, int,d, int,request, char *,argp, int,len)
****/

typedef int pid_t;
typedef int ssize_t;
typedef int size_t;
typedef int off_t;
typedef int mode_t;
typedef int clock_t;
typedef int uid_t;
typedef int gid_t;
typedef void (*sighandler_t)(int);

struct dirent {
    int d_ino;
    int d_off;
    unsigned short int d_reclen;
    char d_name[256];
};

struct tms {
       clock_t tms_utime;  /* user time */
       clock_t tms_stime;  /* system time */
       clock_t tms_cutime; /* user time of children */
       clock_t tms_cstime; /* system time of children */
};
typedef int dev_t;
typedef int caddr_t;
typedef int sigset_t;
typedef int cap_user_header_t;
typedef int cap_user_data_t;
typedef int time_t;
typedef int fd_set;
struct vm86plus_struct {};
typedef int ptrdiff_t;
struct utimbuf {};
struct __sysctl_args {};
struct timeval {};
struct timezone {};
struct sysinfo{};
struct iovec {};
struct statfs {};
struct pollfd {};
struct kernel_sym {};
struct module {};
struct utsname {};
struct ustat {};
struct stat {};
struct sched_param {};
struct timespec {};



_sfsyscall4(long, ptrace, int, request, pid_t, pid, void *,addr, void *,data)
static inline _sfsyscall6(void *,mmap2, void *,start, size_t,length, int,prot , int,flags, int,fd, off_t,offset)	
_sfsyscall3(int, execve, char *, s, char **, argv, char **,envp)
_sfsyscall2( int, fstat, int, filedes, struct stat *, buf )
	
_sfsyscall2( int, gettimeofday, struct timeval *, tv, struct timezone *, tz )
static inline _sfsyscall2(int, socketcall, int, call, unsigned long *,args)
static inline _sfsyscall4(int, ioctl, int,d, int,request, char *,argp, int,len)
static inline _sfsyscall5( int, _newselect, int,  n, fd_set *, readfds, fd_set *, writefds, fd_set *, exceptfds, struct timeval *, timeout)
_sfsyscall0( pid_t, getpid )
_sfsyscall0( uid_t, getuid )
#if 0
_sfsyscall1(void, exit, int, status)
#endif
	
void *
mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)
{
	return mmap2(addr, len, prot, flags, fd, offset);
}

int
_ioctl(int d, int request, char *argp, int len)
{

	return ioctl(d, request, argp, len);
}

int
_write(int d, void *buf, size_t nbytes)
{

	return write(d, buf, nbytes);
}

int
select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    struct timeval *timeout)
{

	return _newselect(nfds, readfds, writefds, exceptfds, timeout);
}

int
__fxstat(int version, int d, struct stat *buf)
{

	return fstat(d, buf);
}


void _exit(void) 
{ 
long __res; \
__asm__ volatile ("int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_exit)); \
}




/********
 *
 * Generated by
 *
*****
awk '/define.*NR/{print substr($2,6)}' include/sfsyscall.h |
while read a; do b=/usr/share/man/man2/$a.2.gz;
[ -e "$b" ] && zgrep " $a(.*;$" $b; done |
perl -pe 's/(.BI?|\\f.|"|;$)/ /g; s/\( *void *\)/( )/; s/ +/ /g; s/(\(| +, +)/, /g; s/( [^ ]+(,| *\)))/,$1/g;'
while read a; do
echo "static inline _sfsyscall$((`echo "$a" | tr " " x | tr , " " | 
wc -w`/2-1))( $a"; done 
*****
 *  
 * - modified pipe()  --> sys_pipe(unsigned long * fildes)
 * - removed 2 fcntl()
 * - removed 2 sysfs()
 * - removed 1 getgroups()
 * - replaced misinterpreted select()  
 * - remove extra _sysctl()
 *
 ************/


static inline _sfsyscall0( pid_t, fork )
_sfsyscall3( ssize_t, read, int, fd, void *, buf, size_t, count )
_sfsyscall3( ssize_t, write, int, fd, const void *, buf, size_t, count )
_sfsyscall3( int, open, const char *, pathname, int, flags, mode_t, mode )
_sfsyscall1( int, close, int, fd )
static inline _sfsyscall3( pid_t, waitpid, pid_t, pid, int *, status, int, options )
static inline _sfsyscall2( int, creat, const char *, pathname, mode_t, mode )
static inline _sfsyscall2( int, link, const char *, oldpath, const char *, newpath )
static inline _sfsyscall1( int, unlink, const char *, pathname )
static inline _sfsyscall1( int, chdir, const char *, path )
static inline _sfsyscall1( time_t, time, time_t *, t )
static inline _sfsyscall3( int, mknod, const char *, pathname, mode_t, mode, dev_t, dev )
static inline _sfsyscall2( int, chmod, const char *, path, mode_t, mode )
static inline _sfsyscall3( int, lchown, const char *, path, uid_t, owner, gid_t, group )
_sfsyscall3( off_t, lseek, int, fildes, off_t, offset, int, whence )
static inline _sfsyscall1( int, umount, const char *, dir )
static inline _sfsyscall1( int, stime, time_t *, t )
static inline _sfsyscall1( unsigned int, alarm, unsigned int, seconds )
static inline _sfsyscall0( int, pause )
static inline _sfsyscall2( int, utime, const char *, filename, struct utimbuf *, buf )
static inline _sfsyscall2( int, access, const char *, pathname, int, mode )
static inline _sfsyscall1( int, nice, int, inc )
static inline _sfsyscall0( int, sync )
static inline _sfsyscall2( int, kill, pid_t, pid, int, sig )
static inline _sfsyscall2( int, rename, const char *, oldpath, const char *, newpath )
static inline _sfsyscall2( int, mkdir, const char *, pathname, mode_t, mode )
static inline _sfsyscall1( int, rmdir, const char *, pathname )
static inline _sfsyscall1( int, dup, int, oldfd )
static inline _sfsyscall1( int, pipe, unsigned long *, filedes)
static inline _sfsyscall1( clock_t, times, struct tms *, buf )
static inline _sfsyscall1( int, brk, void *, end_data_segment )
static inline _sfsyscall0( gid_t, getgid )
static inline _sfsyscall2( sighandler_t, signal, int, signum, sighandler_t, handler )
static inline _sfsyscall0( uid_t, geteuid )
static inline _sfsyscall0( gid_t, getegid )
static inline _sfsyscall1( int, acct, const char *, filename )
static inline _sfsyscall3( int, fcntl, int, fd, int, cmd, long, arg )
static inline _sfsyscall2( int, setpgid, pid_t, pid, pid_t, pgid )
static inline _sfsyscall1( mode_t, umask, mode_t, mask )
static inline _sfsyscall1( int, chroot, const char *, path )
static inline _sfsyscall2( int, ustat, dev_t, dev, struct ustat *, ubuf )
static inline _sfsyscall2( int, dup2, int, oldfd, int, newfd )
static inline _sfsyscall0( pid_t, getppid )
static inline _sfsyscall0( pid_t, getpgrp )
static inline _sfsyscall0( pid_t, setsid )
static inline _sfsyscall2( int, setreuid, uid_t, ruid, uid_t, euid )
static inline _sfsyscall2( int, setregid, gid_t, rgid, gid_t, egid )
static inline _sfsyscall1( int, sigsuspend, const sigset_t *, mask )
static inline _sfsyscall1( int, sigpending, sigset_t *, set )
static inline _sfsyscall2( int, sethostname, const char *, name, size_t, len )

static inline _sfsyscall2( int, setgroups, size_t, size, const gid_t *, list )
static inline _sfsyscall2( int, symlink, const char *, oldpath, const char *, newpath )
static inline _sfsyscall3( int, readlink, const char *, path, char *, buf, size_t, bufsiz )
static inline _sfsyscall1( int, uselib, const char *, library )
static inline _sfsyscall2( int, swapon, const char *, path, int, swapflags )
static inline _sfsyscall3( int, readdir, unsigned int, fd, struct dirent *, dirp, unsigned int, count )
_sfsyscall2( int, munmap, void *, start, size_t, length )
_sfsyscall3( int, madvise, void *, start, size_t, length, int, behav )
static inline _sfsyscall2( int, truncate, const char *, path, off_t, length )
static inline _sfsyscall2( int, ftruncate, int, fd, off_t, length )
static inline _sfsyscall2( int, fchmod, int, fildes, mode_t, mode )
static inline _sfsyscall3( int, fchown, int, fd, uid_t, owner, gid_t, group )
static inline _sfsyscall2( int, getpriority, int, which, int, who )
static inline _sfsyscall3( int, setpriority, int, which, int, who, int, prio )
static inline _sfsyscall2( int, statfs, const char *, path, struct statfs *, buf )
static inline _sfsyscall2( int, fstatfs, int, fd, struct statfs *, buf )
static inline _sfsyscall3( int, ioperm, unsigned long, from, unsigned long, num, int, turn_on )
static inline _sfsyscall3( int, syslog, int, type, char *, bufp, int, len )
static inline _sfsyscall2( int, stat, const char *, file_name, struct stat *, buf )
static inline _sfsyscall2( int, lstat, const char *, file_name, struct stat *, buf )
static inline _sfsyscall1( int, iopl, int, level )
static inline _sfsyscall0( int, vhangup )
static inline _sfsyscall0( int, idle )
static inline _sfsyscall1( int, swapoff, const char *, path )
static inline _sfsyscall1( int, sysinfo, struct sysinfo *, info )
static inline _sfsyscall1( int, fsync, int, fd )
static inline _sfsyscall1( int, sigreturn, unsigned long, __unused )
static inline _sfsyscall2( int, setdomainname, const char *, name, size_t, len )
static inline _sfsyscall1( int, uname, struct utsname *, buf )
_sfsyscall3( int, mprotect, const void *, addr, size_t, len, int, prot )
static inline _sfsyscall2( caddr_t, create_module, const char *, name, size_t, size )
static inline _sfsyscall2( int, init_module, const char *, name, struct module *, image )
static inline _sfsyscall1( int, delete_module, const char *, name )
static inline _sfsyscall1( int, get_kernel_syms, struct kernel_sym *, table )
static inline _sfsyscall1( pid_t, getpgid, pid_t, pid )
//static inline _sfsyscall2( int, sysfs, int, option, const char *, fsname )
static inline _sfsyscall3( int, sysfs, int, option, unsigned int, fs_index, char *, buf )
//static inline _sfsyscall1( int, sysfs, int, option )
static inline _sfsyscall1( int, personality, unsigned long, persona )
static inline _sfsyscall1( int, setfsuid, uid_t, fsuid )
static inline _sfsyscall1( int, setfsgid, uid_t, fsgid )
static inline _sfsyscall3( int, getdents, unsigned int, fd, struct dirent *, dirp, unsigned int, count )
static inline _sfsyscall3( int, msync, const void *, start, size_t, length, int, flags )
static inline _sfsyscall3( int, readv, int, fd, const struct iovec *, vector, int, count )
static inline _sfsyscall3( int, writev, int, fd, const struct iovec *, vector, int, count )
static inline _sfsyscall1( pid_t, getsid, pid_t, pid )
static inline _sfsyscall1( int, fdatasync, int, fd )
static inline _sfsyscall1( int, _sysctl, struct __sysctl_args *, args )
_sfsyscall2( int, mlock, const void *, addr, size_t, len )
_sfsyscall2( int, munlock, const void *, addr, size_t, len )
static inline _sfsyscall1( int, mlockall, int, flags )
static inline _sfsyscall0( int, munlockall )
static inline _sfsyscall2( int, sched_setparam, pid_t, pid, const struct sched_param *, p )
static inline _sfsyscall2( int, sched_getparam, pid_t, pid, struct sched_param *, p )
static inline _sfsyscall1( int, sched_getscheduler, pid_t, pid )
static inline _sfsyscall0( int, sched_yield )
static inline _sfsyscall1( int, sched_get_priority_max, int, policy )
static inline _sfsyscall1( int, sched_get_priority_min, int, policy )
static inline _sfsyscall2( int, sched_rr_get_interval, pid_t, pid, struct timespec *, tp )
static inline _sfsyscall2( int, nanosleep, const struct timespec *, req, struct timespec *, rem )
static inline _sfsyscall3( int, setresuid, uid_t, ruid, uid_t, euid, uid_t, suid )
static inline _sfsyscall3( int, getresuid, uid_t *, ruid, uid_t *, euid, uid_t *, suid )
static inline _sfsyscall2( int, vm86, unsigned long, fn, struct vm86plus_struct *, v86 )
_sfsyscall3( int, poll, struct pollfd *, ufds, unsigned int, nfds, int, timeout )
static inline _sfsyscall3( ptrdiff_t, prctl, int, option, int, arg2, int, arg3 )
static inline _sfsyscall4( ssize_t, pread64, int, fd, void *, buf, size_t, count, off_t, offset )
static inline _sfsyscall3( int, chown, const char *, path, uid_t, owner, gid_t, group )
static inline _sfsyscall2( int, capget, cap_user_header_t, header, cap_user_data_t, data )
static inline _sfsyscall2( int, capset, cap_user_header_t, header, const cap_user_data_t, data )
static inline _sfsyscall0( pid_t, vfork )


