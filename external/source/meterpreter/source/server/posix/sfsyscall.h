/*
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

#ifndef SFSYSCALL_H
#define SFSYSCALL_H

#define __NR_exit		  1
#define __NR_fork		  2
#define __NR_read		  3
#define __NR_write		  4
#define __NR_open		  5
#define __NR_close		  6
#define __NR_waitpid		  7
#define __NR_creat		  8
#define __NR_link		  9
#define __NR_unlink		 10
#define __NR_execve		 11
#define __NR_chdir		 12
#define __NR_time		 13
#define __NR_mknod		 14
#define __NR_chmod		 15
#define __NR_lchown		 16
#define __NR_break		 17
#define __NR_oldstat		 18
#define __NR_lseek		 19
#define __NR_getpid		 20
#define __NR_mount		 21
#define __NR_umount		 22
#define __NR_setuid		 23
#define __NR_getuid		 24
#define __NR_stime		 25
#define __NR_ptrace		 26
#define __NR_alarm		 27
#define __NR_oldfstat		 28
#define __NR_pause		 29
#define __NR_utime		 30
#define __NR_stty		 31
#define __NR_gtty		 32
#define __NR_access		 33
#define __NR_nice		 34
#define __NR_ftime		 35
#define __NR_sync		 36
#define __NR_kill		 37
#define __NR_rename		 38
#define __NR_mkdir		 39
#define __NR_rmdir		 40
#define __NR_dup		 41
#define __NR_pipe		 42
#define __NR_times		 43
#define __NR_prof		 44
#define __NR_brk		 45
#define __NR_setgid		 46
#define __NR_getgid		 47
#define __NR_signal		 48
#define __NR_geteuid		 49
#define __NR_getegid		 50
#define __NR_acct		 51
#define __NR_umount2		 52
#define __NR_lock		 53
#define __NR_ioctl		 54
#define __NR_fcntl		 55
#define __NR_mpx		 56
#define __NR_setpgid		 57
#define __NR_ulimit		 58
#define __NR_oldolduname	 59
#define __NR_umask		 60
#define __NR_chroot		 61
#define __NR_ustat		 62
#define __NR_dup2		 63
#define __NR_getppid		 64
#define __NR_getpgrp		 65
#define __NR_setsid		 66
#define __NR_sigaction		 67
#define __NR_sgetmask		 68
#define __NR_ssetmask		 69
#define __NR_setreuid		 70
#define __NR_setregid		 71
#define __NR_sigsuspend		 72
#define __NR_sigpending		 73
#define __NR_sethostname	 74
#define __NR_setrlimit		 75
#define __NR_oldgetrlimit		 76
#define __NR_getrusage		 77
#define __NR_gettimeofday	 78
#define __NR_settimeofday	 79
#define __NR_getgroups		 80
#define __NR_setgroups		 81
#define __NR_select		 82
#define __NR_symlink		 83
#define __NR_oldlstat		 84
#define __NR_readlink		 85
#define __NR_uselib		 86
#define __NR_swapon		 87
#define __NR_reboot		 88
#define __NR_readdir		 89
#define __NR_oldmmap		 90
#define __NR_munmap		 91
#define __NR_truncate		 92
#define __NR_ftruncate		 93
#define __NR_fchmod		 94
#define __NR_fchown		 95
#define __NR_getpriority	 96
#define __NR_setpriority	 97
#define __NR_profil		 98
#define __NR_statfs		 99
#define __NR_fstatfs		100
#define __NR_ioperm		101
#define __NR_socketcall		102
#define __NR_syslog		103
#define __NR_setitimer		104
#define __NR_getitimer		105
#define __NR_stat		106
#define __NR_lstat		107
#define __NR_fstat		108
#define __NR_olduname		109
#define __NR_iopl		110
#define __NR_vhangup		111
#define __NR_idle		112
#define __NR_vm86old		113
#define __NR_wait4		114
#define __NR_swapoff		115
#define __NR_sysinfo		116
#define __NR_ipc		117
#define __NR_fsync		118
#define __NR_sigreturn		119
#define __NR_clone		120
#define __NR_setdomainname	121
#define __NR_uname		122
#define __NR_modify_ldt		123
#define __NR_adjtimex		124
#define __NR_mprotect		125
#define __NR_sigprocmask	126
#define __NR_create_module	127
#define __NR_init_module	128
#define __NR_delete_module	129
#define __NR_get_kernel_syms	130
#define __NR_quotactl		131
#define __NR_getpgid		132
#define __NR_fchdir		133
#define __NR_bdflush		134
#define __NR_sysfs		135
#define __NR_personality	136
#define __NR_afs_syscall	137 /* Syscall for Andrew File System */
#define __NR_setfsuid		138
#define __NR_setfsgid		139
#define __NR__llseek		140
#define __NR_getdents		141
#define __NR__newselect		142
#define __NR_flock		143
#define __NR_msync		144
#define __NR_readv		145
#define __NR_writev		146
#define __NR_getsid		147
#define __NR_fdatasync		148
#define __NR__sysctl		149
#define __NR_mlock		150
#define __NR_munlock		151
#define __NR_mlockall		152
#define __NR_munlockall		153
#define __NR_sched_setparam		154
#define __NR_sched_getparam		155
#define __NR_sched_setscheduler		156
#define __NR_sched_getscheduler		157
#define __NR_sched_yield		158
#define __NR_sched_get_priority_max	159
#define __NR_sched_get_priority_min	160
#define __NR_sched_rr_get_interval	161
#define __NR_nanosleep		162
#define __NR_mremap		163
#define __NR_setresuid		164
#define __NR_getresuid		165
#define __NR_vm86		166
#define __NR_query_module	167
#define __NR_poll		168
#define __NR_nfsservctl		169
#define __NR_setresgid		170
#define __NR_getresgid		171
#define __NR_prctl              172
#define __NR_rt_sigreturn	173
#define __NR_rt_sigaction	174
#define __NR_rt_sigprocmask	175
#define __NR_rt_sigpending	176
#define __NR_rt_sigtimedwait	177
#define __NR_rt_sigqueueinfo	178
#define __NR_rt_sigsuspend	179
#define __NR_pread		180
#define __NR_pwrite		181
#define __NR_chown		182
#define __NR_getcwd		183
#define __NR_capget		184
#define __NR_capset		185
#define __NR_sigaltstack	186
#define __NR_sendfile		187
#define __NR_getpmsg		188	/* some people actually want streams */
#define __NR_putpmsg		189	/* some people actually want streams */
#define __NR_vfork		190
#define __NR_getrlimit		191
#define __NR_mmap		192

/* Remove errno stuff */
#define __sfsyscall_return(type, res) \
do { \
	return (type) (res); \
} while (0)

/* XXX - _foo needs to be __foo, while __NR_bar could be _NR_bar. */
#define _sfsyscall0(type,name) \
type _##name(void) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_##name)); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall1(type,name,type1,arg1) \
type _##name(type1 arg1) \
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
type _##name(type1 arg1,type2 arg2) \
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
type _##name(type1 arg1,type2 arg2,type3 arg3) \
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
type _##name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
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
type _##name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
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
type _##name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5, type6 arg6) \
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
type _##name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5, type6 arg6) \
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

/******** Some constants *********/

#define O_RDONLY    00
#define O_WRONLY    01
#define O_RDWR      02
#define O_CREAT   0100
#define O_TRUNC  01000
#define O_APPEND 02000


/******** Syscalls *********/


/****
static inline _sfsyscall3(int, read, int, fd, void *, buf, long, count)
static inline _sfsyscall3(int, write, int, fd, void *, buf, long, count)
static inline _sfsyscall3(int, execve, char *, s, char **, argv, char **,envp)
static inline _sfsyscall1(int, close, int, fd)
static inline _sfsyscall3(int, open, char *, path, int, mode, int, flags)

static inline _sfsyscall2(int, setreuid, int, reuid, int, euid)
static inline _sfsyscall1(int, chroot, char *,path)
static inline _sfsyscall1(int, dup, int, fd)

static inline _sfsyscall2(int, dup2, int, ofd, int, nfd)

static inline _sfsyscall1(int, chdir, char *, path)
static inline _sfsyscall3(int, chown, char *, path, int, uid, int, gid)
static inline _sfsyscall2(int, chmod, char *, path, int, mode)
static inline _sfsyscall0(int, fork)
static inline _sfsyscall1(int, exit, int, status)
static inline _sfsyscall0(int, getuid)
static inline _sfsyscall0(int, geteuid)
static inline _sfsyscall2(int, socketcall, int, call, unsigned long *,args)
static inline _sfsyscall4(int, ioctl, int,d, int,request, char *,argp, int,len)
****/

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
typedef int cap_user_header_t;
typedef int cap_user_data_t;
struct vm86plus_struct {};
typedef int ptrdiff_t;
struct utimbuf {};
struct __sysctl_args {};
struct timezone {};
struct sysinfo{};
struct statfs {};
struct pollfd {};
struct kernel_sym {};
struct module {};
struct utsname {};
struct ustat {};
struct stat {};
struct sched_param {};




static inline _sfsyscall3(int, execve, char *, s, char **, argv, char **,envp)
static inline _sfsyscall1(int, exit, int, status)
static inline _sfsyscall2(int, socketcall, int, call, unsigned long *,args)
static inline _sfsyscall4(int, ioctl, int,d, int,request, char *,argp, int,len)
static inline _sfsyscall4(long, ptrace, int, request, pid_t, pid, void *,addr, void *,data)

static inline _sfsyscall6(void *,mmap, void *,start, size_t,length, int,prot , int,flags, int,fd, off_t,offset)
static inline _sfoldsyscall6(void *,oldmmap, void *,start, size_t,length, int,prot , int,flags, int,fd, off_t,offset)









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
static inline _sfsyscall3( ssize_t, read, int, fd, void *, buf, size_t, count )
static inline _sfsyscall3( ssize_t, write, int, fd, const void *, buf, size_t, count )
static inline _sfsyscall3( int, open, const char *, pathname, int, flags, mode_t, mode )
static inline _sfsyscall1( int, close, int, fd )
static inline _sfsyscall3( pid_t, waitpid, pid_t, pid, int *, status, int, options )
static inline _sfsyscall2( int, creat, const char *, pathname, mode_t, mode )
static inline _sfsyscall2( int, link, const char *, oldpath, const char *, newpath )
static inline _sfsyscall1( int, unlink, const char *, pathname )
static inline _sfsyscall1( int, chdir, const char *, path )
static inline _sfsyscall1( time_t, time, time_t *, t )
static inline _sfsyscall3( int, mknod, const char *, pathname, mode_t, mode, dev_t, dev )
static inline _sfsyscall2( int, chmod, const char *, path, mode_t, mode )
static inline _sfsyscall3( int, lchown, const char *, path, uid_t, owner, gid_t, group )
static inline _sfsyscall3( off_t, lseek, int, fildes, off_t, offset, int, whence )
static inline _sfsyscall0( pid_t, getpid )
static inline _sfsyscall1( int, umount, const char *, dir )
static inline _sfsyscall0( uid_t, getuid )
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
static inline _sfsyscall2( int, gettimeofday, struct timeval *, tv, struct timezone *, tz )
static inline _sfsyscall2( int, setgroups, size_t, size, const gid_t *, list )
static inline _sfsyscall5( int, select, int,  n, fd_set *, readfds, fd_set *, writefds, fd_set *, exceptfds, struct timeval *, timeout)
static inline _sfsyscall2( int, symlink, const char *, oldpath, const char *, newpath )
static inline _sfsyscall3( int, readlink, const char *, path, char *, buf, size_t, bufsiz )
static inline _sfsyscall1( int, uselib, const char *, library )
static inline _sfsyscall2( int, swapon, const char *, path, int, swapflags )
static inline _sfsyscall3( int, readdir, unsigned int, fd, struct dirent *, dirp, unsigned int, count )
static inline _sfsyscall2( int, munmap, void *, start, size_t, length )
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
static inline _sfsyscall2( int, fstat, int, filedes, struct stat *, buf )
static inline _sfsyscall1( int, iopl, int, level )
static inline _sfsyscall0( int, vhangup )
static inline _sfsyscall0( int, idle )
static inline _sfsyscall1( int, swapoff, const char *, path )
static inline _sfsyscall1( int, sysinfo, struct sysinfo *, info )
static inline _sfsyscall1( int, fsync, int, fd )
#ifdef notyet
static inline _sfsyscall1( int, sigreturn, unsigned long, __unused )
#endif
static inline _sfsyscall2( int, setdomainname, const char *, name, size_t, len )
static inline _sfsyscall1( int, uname, struct utsname *, buf )
static inline _sfsyscall3( int, mprotect, const void *, addr, size_t, len, int, prot )
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
static inline _sfsyscall2( int, mlock, const void *, addr, size_t, len )
static inline _sfsyscall2( int, munlock, const void *, addr, size_t, len )
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
static inline _sfsyscall3( int, poll, struct pollfd *, ufds, unsigned int, nfds, int, timeout )
static inline _sfsyscall3( ptrdiff_t, prctl, int, option, int, arg2, int, arg3 )
static inline _sfsyscall4( ssize_t, pread, int, fd, void *, buf, size_t, count, off_t, offset )
static inline _sfsyscall3( int, chown, const char *, path, uid_t, owner, gid_t, group )
static inline _sfsyscall2( int, capget, cap_user_header_t, header, cap_user_data_t, data )
static inline _sfsyscall2( int, capset, cap_user_header_t, header, const cap_user_data_t, data )
static inline _sfsyscall0( pid_t, vfork )



#endif
