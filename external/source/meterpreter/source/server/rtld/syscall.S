/* 
 * PKS, copied from bionic sysall.S code..
 * 
 * Changes: save/restore/use ebp for mmap() syscall.
 *          don't restore eax on syscall return :~(
 */

/*
 * Generic syscall call.
 * Upon entry
 *	%eax: system call number
 *	%ebx: arg0 to system call
 *	%ecx: arg..
 *	%edx: arg..
 *	%esi: arg..
 *	%edi: arg..
 * We push these (to save them) load them up with the
 * values from the calling frame (not all will actually be valid)
 * and make the syscall.
 */

    .text
    .type syscall, @function
    .globl syscall
    .align 4

syscall:
    /* push    %eax .. fucking google. */
    push    %ebx
    push    %ecx
    push    %edx
    push    %esi
    push    %edi
    push    %ebp
    mov     28(%esp),%eax
    mov     32(%esp),%ebx
    mov     36(%esp),%ecx
    mov     40(%esp),%edx
    mov     44(%esp),%esi
    mov     48(%esp),%edi
    mov     52(%esp),%ebp

    int     $0x80

    cmpl    $-129, %eax
    jb      1f
    negl    %eax
    pushl   %eax
    call    __set_errno
    addl    $4, %esp
    orl     $-1, %eax

1:
    pop    %ebp
    pop    %edi
    pop    %esi
    pop    %edx
    pop    %ecx
    pop    %ebx
    /* pop    %eax ... this took ages :( */
    ret

/* 
 * This is about the hackiest implementation of syscalls, you'll ever see! 
 * 
 * Generated the below via a quick shellscript. 
 */

.text
.type exit, @function
.globl exit
.align 4
exit:
pop %edx /* save return address */
push $1
call syscall
add $4, %esp
push %edx
ret

.text
.type fork, @function
.globl fork
.align 4
fork:
pop %edx /* save return address */
push $2
call syscall
add $4, %esp
push %edx
ret

.text
.type read, @function
.globl read
.align 4
read:
pop %edx /* save return address */
push $3
call syscall
add $4, %esp
push %edx
ret

.text
.type write, @function
.globl write
.align 4
write:
pop %edx /* save return address */
push $4
call syscall
add $4, %esp
push %edx
ret

.text
.type open, @function
.globl open
.align 4
open:
pop %edx /* save return address */
push $5
call syscall
add $4, %esp
push %edx
ret

.text
.type close, @function
.globl close
.align 4
close:
pop %edx /* save return address */
push $6
call syscall
add $4, %esp
push %edx
ret

.text
.type waitpid, @function
.globl waitpid
.align 4
waitpid:
pop %edx /* save return address */
push $7
call syscall
add $4, %esp
push %edx
ret

.text
.type creat, @function
.globl creat
.align 4
creat:
pop %edx /* save return address */
push $8
call syscall
add $4, %esp
push %edx
ret

.text
.type link, @function
.globl link
.align 4
link:
pop %edx /* save return address */
push $9
call syscall
add $4, %esp
push %edx
ret

.text
.type unlink, @function
.globl unlink
.align 4
unlink:
pop %edx /* save return address */
push $10
call syscall
add $4, %esp
push %edx
ret

.text
.type execve, @function
.globl execve
.align 4
execve:
pop %edx /* save return address */
push $11
call syscall
add $4, %esp
push %edx
ret

.text
.type chdir, @function
.globl chdir
.align 4
chdir:
pop %edx /* save return address */
push $12
call syscall
add $4, %esp
push %edx
ret

.text
.type time, @function
.globl time
.align 4
time:
pop %edx /* save return address */
push $13
call syscall
add $4, %esp
push %edx
ret

.text
.type mknod, @function
.globl mknod
.align 4
mknod:
pop %edx /* save return address */
push $14
call syscall
add $4, %esp
push %edx
ret

.text
.type chmod, @function
.globl chmod
.align 4
chmod:
pop %edx /* save return address */
push $15
call syscall
add $4, %esp
push %edx
ret

.text
.type lchown, @function
.globl lchown
.align 4
lchown:
pop %edx /* save return address */
push $16
call syscall
add $4, %esp
push %edx
ret

.text
.type break, @function
.globl break
.align 4
break:
pop %edx /* save return address */
push $17
call syscall
add $4, %esp
push %edx
ret

.text
.type oldstat, @function
.globl oldstat
.align 4
oldstat:
pop %edx /* save return address */
push $18
call syscall
add $4, %esp
push %edx
ret

.text
.type lseek, @function
.globl lseek
.align 4
lseek:
pop %edx /* save return address */
push $19
call syscall
add $4, %esp
push %edx
ret

.text
.type getpid, @function
.globl getpid
.align 4
getpid:
pop %edx /* save return address */
push $20
call syscall
add $4, %esp
push %edx
ret

.text
.type mount, @function
.globl mount
.align 4
mount:
pop %edx /* save return address */
push $21
call syscall
add $4, %esp
push %edx
ret

.text
.type umount, @function
.globl umount
.align 4
umount:
pop %edx /* save return address */
push $22
call syscall
add $4, %esp
push %edx
ret

.text
.type setuid, @function
.globl setuid
.align 4
setuid:
pop %edx /* save return address */
push $23
call syscall
add $4, %esp
push %edx
ret

.text
.type getuid, @function
.globl getuid
.align 4
getuid:
pop %edx /* save return address */
push $24
call syscall
add $4, %esp
push %edx
ret

.text
.type stime, @function
.globl stime
.align 4
stime:
pop %edx /* save return address */
push $25
call syscall
add $4, %esp
push %edx
ret

.text
.type ptrace, @function
.globl ptrace
.align 4
ptrace:
pop %edx /* save return address */
push $26
call syscall
add $4, %esp
push %edx
ret

.text
.type alarm, @function
.globl alarm
.align 4
alarm:
pop %edx /* save return address */
push $27
call syscall
add $4, %esp
push %edx
ret

.text
.type oldfstat, @function
.globl oldfstat
.align 4
oldfstat:
pop %edx /* save return address */
push $28
call syscall
add $4, %esp
push %edx
ret

.text
.type pause, @function
.globl pause
.align 4
pause:
pop %edx /* save return address */
push $29
call syscall
add $4, %esp
push %edx
ret

.text
.type utime, @function
.globl utime
.align 4
utime:
pop %edx /* save return address */
push $30
call syscall
add $4, %esp
push %edx
ret

.text
.type stty, @function
.globl stty
.align 4
stty:
pop %edx /* save return address */
push $31
call syscall
add $4, %esp
push %edx
ret

.text
.type gtty, @function
.globl gtty
.align 4
gtty:
pop %edx /* save return address */
push $32
call syscall
add $4, %esp
push %edx
ret

.text
.type access, @function
.globl access
.align 4
access:
pop %edx /* save return address */
push $33
call syscall
add $4, %esp
push %edx
ret

.text
.type nice, @function
.globl nice
.align 4
nice:
pop %edx /* save return address */
push $34
call syscall
add $4, %esp
push %edx
ret

.text
.type ftime, @function
.globl ftime
.align 4
ftime:
pop %edx /* save return address */
push $35
call syscall
add $4, %esp
push %edx
ret

.text
.type sync, @function
.globl sync
.align 4
sync:
pop %edx /* save return address */
push $36
call syscall
add $4, %esp
push %edx
ret

.text
.type kill, @function
.globl kill
.align 4
kill:
pop %edx /* save return address */
push $37
call syscall
add $4, %esp
push %edx
ret

.text
.type rename, @function
.globl rename
.align 4
rename:
pop %edx /* save return address */
push $38
call syscall
add $4, %esp
push %edx
ret

.text
.type mkdir, @function
.globl mkdir
.align 4
mkdir:
pop %edx /* save return address */
push $39
call syscall
add $4, %esp
push %edx
ret

.text
.type rmdir, @function
.globl rmdir
.align 4
rmdir:
pop %edx /* save return address */
push $40
call syscall
add $4, %esp
push %edx
ret

.text
.type dup, @function
.globl dup
.align 4
dup:
pop %edx /* save return address */
push $41
call syscall
add $4, %esp
push %edx
ret

.text
.type pipe, @function
.globl pipe
.align 4
pipe:
pop %edx /* save return address */
push $42
call syscall
add $4, %esp
push %edx
ret

.text
.type times, @function
.globl times
.align 4
times:
pop %edx /* save return address */
push $43
call syscall
add $4, %esp
push %edx
ret

.text
.type prof, @function
.globl prof
.align 4
prof:
pop %edx /* save return address */
push $44
call syscall
add $4, %esp
push %edx
ret

.text
.type brk, @function
.globl brk
.align 4
brk:
pop %edx /* save return address */
push $45
call syscall
add $4, %esp
push %edx
ret

.text
.type setgid, @function
.globl setgid
.align 4
setgid:
pop %edx /* save return address */
push $46
call syscall
add $4, %esp
push %edx
ret

.text
.type getgid, @function
.globl getgid
.align 4
getgid:
pop %edx /* save return address */
push $47
call syscall
add $4, %esp
push %edx
ret

.text
.type signal, @function
.globl signal
.align 4
signal:
pop %edx /* save return address */
push $48
call syscall
add $4, %esp
push %edx
ret

.text
.type geteuid, @function
.globl geteuid
.align 4
geteuid:
pop %edx /* save return address */
push $49
call syscall
add $4, %esp
push %edx
ret

.text
.type getegid, @function
.globl getegid
.align 4
getegid:
pop %edx /* save return address */
push $50
call syscall
add $4, %esp
push %edx
ret

.text
.type acct, @function
.globl acct
.align 4
acct:
pop %edx /* save return address */
push $51
call syscall
add $4, %esp
push %edx
ret

.text
.type umount2, @function
.globl umount2
.align 4
umount2:
pop %edx /* save return address */
push $52
call syscall
add $4, %esp
push %edx
ret

.text
.type lock, @function
.globl lock
.align 4
lock:
pop %edx /* save return address */
push $53
call syscall
add $4, %esp
push %edx
ret

.text
.type ioctl, @function
.globl ioctl
.align 4
ioctl:
pop %edx /* save return address */
push $54
call syscall
add $4, %esp
push %edx
ret

.text
.type fcntl, @function
.globl fcntl
.align 4
fcntl:
pop %edx /* save return address */
push $55
call syscall
add $4, %esp
push %edx
ret

.text
.type mpx, @function
.globl mpx
.align 4
mpx:
pop %edx /* save return address */
push $56
call syscall
add $4, %esp
push %edx
ret

.text
.type setpgid, @function
.globl setpgid
.align 4
setpgid:
pop %edx /* save return address */
push $57
call syscall
add $4, %esp
push %edx
ret

.text
.type ulimit, @function
.globl ulimit
.align 4
ulimit:
pop %edx /* save return address */
push $58
call syscall
add $4, %esp
push %edx
ret

.text
.type oldolduname, @function
.globl oldolduname
.align 4
oldolduname:
pop %edx /* save return address */
push $59
call syscall
add $4, %esp
push %edx
ret

.text
.type umask, @function
.globl umask
.align 4
umask:
pop %edx /* save return address */
push $60
call syscall
add $4, %esp
push %edx
ret

.text
.type chroot, @function
.globl chroot
.align 4
chroot:
pop %edx /* save return address */
push $61
call syscall
add $4, %esp
push %edx
ret

.text
.type ustat, @function
.globl ustat
.align 4
ustat:
pop %edx /* save return address */
push $62
call syscall
add $4, %esp
push %edx
ret

.text
.type dup2, @function
.globl dup2
.align 4
dup2:
pop %edx /* save return address */
push $63
call syscall
add $4, %esp
push %edx
ret

.text
.type getppid, @function
.globl getppid
.align 4
getppid:
pop %edx /* save return address */
push $64
call syscall
add $4, %esp
push %edx
ret

.text
.type getpgrp, @function
.globl getpgrp
.align 4
getpgrp:
pop %edx /* save return address */
push $65
call syscall
add $4, %esp
push %edx
ret

.text
.type setsid, @function
.globl setsid
.align 4
setsid:
pop %edx /* save return address */
push $66
call syscall
add $4, %esp
push %edx
ret

.text
.type sigaction, @function
.globl sigaction
.align 4
sigaction:
pop %edx /* save return address */
push $67
call syscall
add $4, %esp
push %edx
ret

.text
.type sgetmask, @function
.globl sgetmask
.align 4
sgetmask:
pop %edx /* save return address */
push $68
call syscall
add $4, %esp
push %edx
ret

.text
.type ssetmask, @function
.globl ssetmask
.align 4
ssetmask:
pop %edx /* save return address */
push $69
call syscall
add $4, %esp
push %edx
ret

.text
.type setreuid, @function
.globl setreuid
.align 4
setreuid:
pop %edx /* save return address */
push $70
call syscall
add $4, %esp
push %edx
ret

.text
.type setregid, @function
.globl setregid
.align 4
setregid:
pop %edx /* save return address */
push $71
call syscall
add $4, %esp
push %edx
ret

.text
.type sigsuspend, @function
.globl sigsuspend
.align 4
sigsuspend:
pop %edx /* save return address */
push $72
call syscall
add $4, %esp
push %edx
ret

.text
.type sigpending, @function
.globl sigpending
.align 4
sigpending:
pop %edx /* save return address */
push $73
call syscall
add $4, %esp
push %edx
ret

.text
.type sethostname, @function
.globl sethostname
.align 4
sethostname:
pop %edx /* save return address */
push $74
call syscall
add $4, %esp
push %edx
ret

.text
.type setrlimit, @function
.globl setrlimit
.align 4
setrlimit:
pop %edx /* save return address */
push $75
call syscall
add $4, %esp
push %edx
ret

.text
.type oldgetrlimit, @function
.globl oldgetrlimit
.align 4
oldgetrlimit:
pop %edx /* save return address */
push $76
call syscall
add $4, %esp
push %edx
ret

.text
.type getrusage, @function
.globl getrusage
.align 4
getrusage:
pop %edx /* save return address */
push $77
call syscall
add $4, %esp
push %edx
ret

.text
.type gettimeofday, @function
.globl gettimeofday
.align 4
gettimeofday:
pop %edx /* save return address */
push $78
call syscall
add $4, %esp
push %edx
ret

.text
.type settimeofday, @function
.globl settimeofday
.align 4
settimeofday:
pop %edx /* save return address */
push $79
call syscall
add $4, %esp
push %edx
ret

.text
.type getgroups, @function
.globl getgroups
.align 4
getgroups:
pop %edx /* save return address */
push $80
call syscall
add $4, %esp
push %edx
ret

.text
.type setgroups, @function
.globl setgroups
.align 4
setgroups:
pop %edx /* save return address */
push $81
call syscall
add $4, %esp
push %edx
ret

.text
.type select, @function
.globl select
.align 4
select:
pop %edx /* save return address */
push $82
call syscall
add $4, %esp
push %edx
ret

.text
.type symlink, @function
.globl symlink
.align 4
symlink:
pop %edx /* save return address */
push $83
call syscall
add $4, %esp
push %edx
ret

.text
.type oldlstat, @function
.globl oldlstat
.align 4
oldlstat:
pop %edx /* save return address */
push $84
call syscall
add $4, %esp
push %edx
ret

.text
.type readlink, @function
.globl readlink
.align 4
readlink:
pop %edx /* save return address */
push $85
call syscall
add $4, %esp
push %edx
ret

.text
.type uselib, @function
.globl uselib
.align 4
uselib:
pop %edx /* save return address */
push $86
call syscall
add $4, %esp
push %edx
ret

.text
.type swapon, @function
.globl swapon
.align 4
swapon:
pop %edx /* save return address */
push $87
call syscall
add $4, %esp
push %edx
ret

.text
.type reboot, @function
.globl reboot
.align 4
reboot:
pop %edx /* save return address */
push $88
call syscall
add $4, %esp
push %edx
ret

.text
.type readdir, @function
.globl readdir
.align 4
readdir:
pop %edx /* save return address */
push $89
call syscall
add $4, %esp
push %edx
ret

.text
.type oldmmap, @function
.globl oldmmap
.align 4
oldmmap:
pop %edx /* save return address */
push $90
call syscall
add $4, %esp
push %edx
ret

.text
.type munmap, @function
.globl munmap
.align 4
munmap:
pop %edx /* save return address */
push $91
call syscall
add $4, %esp
push %edx
ret

.text
.type truncate, @function
.globl truncate
.align 4
truncate:
pop %edx /* save return address */
push $92
call syscall
add $4, %esp
push %edx
ret

.text
.type ftruncate, @function
.globl ftruncate
.align 4
ftruncate:
pop %edx /* save return address */
push $93
call syscall
add $4, %esp
push %edx
ret

.text
.type fchmod, @function
.globl fchmod
.align 4
fchmod:
pop %edx /* save return address */
push $94
call syscall
add $4, %esp
push %edx
ret

.text
.type fchown, @function
.globl fchown
.align 4
fchown:
pop %edx /* save return address */
push $95
call syscall
add $4, %esp
push %edx
ret

.text
.type getpriority, @function
.globl getpriority
.align 4
getpriority:
pop %edx /* save return address */
push $96
call syscall
add $4, %esp
push %edx
ret

.text
.type setpriority, @function
.globl setpriority
.align 4
setpriority:
pop %edx /* save return address */
push $97
call syscall
add $4, %esp
push %edx
ret

.text
.type profil, @function
.globl profil
.align 4
profil:
pop %edx /* save return address */
push $98
call syscall
add $4, %esp
push %edx
ret

.text
.type statfs, @function
.globl statfs
.align 4
statfs:
pop %edx /* save return address */
push $99
call syscall
add $4, %esp
push %edx
ret

.text
.type fstatfs, @function
.globl fstatfs
.align 4
fstatfs:
pop %edx /* save return address */
push $100
call syscall
add $4, %esp
push %edx
ret

.text
.type ioperm, @function
.globl ioperm
.align 4
ioperm:
pop %edx /* save return address */
push $101
call syscall
add $4, %esp
push %edx
ret

.text
.type socketcall, @function
.globl socketcall
.align 4
socketcall:
pop %edx /* save return address */
push $102
call syscall
add $4, %esp
push %edx
ret

.text
.type syslog, @function
.globl syslog
.align 4
syslog:
pop %edx /* save return address */
push $103
call syscall
add $4, %esp
push %edx
ret

.text
.type setitimer, @function
.globl setitimer
.align 4
setitimer:
pop %edx /* save return address */
push $104
call syscall
add $4, %esp
push %edx
ret

.text
.type getitimer, @function
.globl getitimer
.align 4
getitimer:
pop %edx /* save return address */
push $105
call syscall
add $4, %esp
push %edx
ret

.text
.type stat, @function
.globl stat
.align 4
stat:
pop %edx /* save return address */
push $106
call syscall
add $4, %esp
push %edx
ret

.text
.type lstat, @function
.globl lstat
.align 4
lstat:
pop %edx /* save return address */
push $107
call syscall
add $4, %esp
push %edx
ret

.text
.type fstat, @function
.globl fstat
.align 4
fstat:
pop %edx /* save return address */
push $108
call syscall
add $4, %esp
push %edx
ret

.text
.type olduname, @function
.globl olduname
.align 4
olduname:
pop %edx /* save return address */
push $109
call syscall
add $4, %esp
push %edx
ret

.text
.type iopl, @function
.globl iopl
.align 4
iopl:
pop %edx /* save return address */
push $110
call syscall
add $4, %esp
push %edx
ret

.text
.type vhangup, @function
.globl vhangup
.align 4
vhangup:
pop %edx /* save return address */
push $111
call syscall
add $4, %esp
push %edx
ret

.text
.type idle, @function
.globl idle
.align 4
idle:
pop %edx /* save return address */
push $112
call syscall
add $4, %esp
push %edx
ret

.text
.type vm86old, @function
.globl vm86old
.align 4
vm86old:
pop %edx /* save return address */
push $113
call syscall
add $4, %esp
push %edx
ret

.text
.type wait4, @function
.globl wait4
.align 4
wait4:
pop %edx /* save return address */
push $114
call syscall
add $4, %esp
push %edx
ret

.text
.type swapoff, @function
.globl swapoff
.align 4
swapoff:
pop %edx /* save return address */
push $115
call syscall
add $4, %esp
push %edx
ret

.text
.type sysinfo, @function
.globl sysinfo
.align 4
sysinfo:
pop %edx /* save return address */
push $116
call syscall
add $4, %esp
push %edx
ret

.text
.type ipc, @function
.globl ipc
.align 4
ipc:
pop %edx /* save return address */
push $117
call syscall
add $4, %esp
push %edx
ret

.text
.type fsync, @function
.globl fsync
.align 4
fsync:
pop %edx /* save return address */
push $118
call syscall
add $4, %esp
push %edx
ret

.text
.type sigreturn, @function
.globl sigreturn
.align 4
sigreturn:
pop %edx /* save return address */
push $119
call syscall
add $4, %esp
push %edx
ret

.text
.type clone, @function
.globl clone
.align 4
clone:
pop %edx /* save return address */
push $120
call syscall
add $4, %esp
push %edx
ret

.text
.type setdomainname, @function
.globl setdomainname
.align 4
setdomainname:
pop %edx /* save return address */
push $121
call syscall
add $4, %esp
push %edx
ret

.text
.type uname, @function
.globl uname
.align 4
uname:
pop %edx /* save return address */
push $122
call syscall
add $4, %esp
push %edx
ret

.text
.type modify_ldt, @function
.globl modify_ldt
.align 4
modify_ldt:
pop %edx /* save return address */
push $123
call syscall
add $4, %esp
push %edx
ret

.text
.type adjtimex, @function
.globl adjtimex
.align 4
adjtimex:
pop %edx /* save return address */
push $124
call syscall
add $4, %esp
push %edx
ret

.text
.type mprotect, @function
.globl mprotect
.align 4
mprotect:
pop %edx /* save return address */
push $125
call syscall
add $4, %esp
push %edx
ret

.text
.type sigprocmask, @function
.globl sigprocmask
.align 4
sigprocmask:
pop %edx /* save return address */
push $126
call syscall
add $4, %esp
push %edx
ret

.text
.type create_module, @function
.globl create_module
.align 4
create_module:
pop %edx /* save return address */
push $127
call syscall
add $4, %esp
push %edx
ret

.text
.type init_module, @function
.globl init_module
.align 4
init_module:
pop %edx /* save return address */
push $128
call syscall
add $4, %esp
push %edx
ret

.text
.type delete_module, @function
.globl delete_module
.align 4
delete_module:
pop %edx /* save return address */
push $129
call syscall
add $4, %esp
push %edx
ret

.text
.type get_kernel_syms, @function
.globl get_kernel_syms
.align 4
get_kernel_syms:
pop %edx /* save return address */
push $130
call syscall
add $4, %esp
push %edx
ret

.text
.type quotactl, @function
.globl quotactl
.align 4
quotactl:
pop %edx /* save return address */
push $131
call syscall
add $4, %esp
push %edx
ret

.text
.type getpgid, @function
.globl getpgid
.align 4
getpgid:
pop %edx /* save return address */
push $132
call syscall
add $4, %esp
push %edx
ret

.text
.type fchdir, @function
.globl fchdir
.align 4
fchdir:
pop %edx /* save return address */
push $133
call syscall
add $4, %esp
push %edx
ret

.text
.type bdflush, @function
.globl bdflush
.align 4
bdflush:
pop %edx /* save return address */
push $134
call syscall
add $4, %esp
push %edx
ret

.text
.type sysfs, @function
.globl sysfs
.align 4
sysfs:
pop %edx /* save return address */
push $135
call syscall
add $4, %esp
push %edx
ret

.text
.type personality, @function
.globl personality
.align 4
personality:
pop %edx /* save return address */
push $136
call syscall
add $4, %esp
push %edx
ret

.text
.type afs_syscall, @function
.globl afs_syscall
.align 4
afs_syscall:
pop %edx /* save return address */
push $137
call syscall
add $4, %esp
push %edx
ret

.text
.type setfsuid, @function
.globl setfsuid
.align 4
setfsuid:
pop %edx /* save return address */
push $138
call syscall
add $4, %esp
push %edx
ret

.text
.type setfsgid, @function
.globl setfsgid
.align 4
setfsgid:
pop %edx /* save return address */
push $139
call syscall
add $4, %esp
push %edx
ret

.text
.type _llseek, @function
.globl _llseek
.align 4
_llseek:
pop %edx /* save return address */
push $140
call syscall
add $4, %esp
push %edx
ret

.text
.type getdents, @function
.globl getdents
.align 4
getdents:
pop %edx /* save return address */
push $141
call syscall
add $4, %esp
push %edx
ret

.text
.type _newselect, @function
.globl _newselect
.align 4
_newselect:
pop %edx /* save return address */
push $142
call syscall
add $4, %esp
push %edx
ret

.text
.type flock, @function
.globl flock
.align 4
flock:
pop %edx /* save return address */
push $143
call syscall
add $4, %esp
push %edx
ret

.text
.type msync, @function
.globl msync
.align 4
msync:
pop %edx /* save return address */
push $144
call syscall
add $4, %esp
push %edx
ret

.text
.type readv, @function
.globl readv
.align 4
readv:
pop %edx /* save return address */
push $145
call syscall
add $4, %esp
push %edx
ret

.text
.type writev, @function
.globl writev
.align 4
writev:
pop %edx /* save return address */
push $146
call syscall
add $4, %esp
push %edx
ret

.text
.type getsid, @function
.globl getsid
.align 4
getsid:
pop %edx /* save return address */
push $147
call syscall
add $4, %esp
push %edx
ret

.text
.type fdatasync, @function
.globl fdatasync
.align 4
fdatasync:
pop %edx /* save return address */
push $148
call syscall
add $4, %esp
push %edx
ret

.text
.type _sysctl, @function
.globl _sysctl
.align 4
_sysctl:
pop %edx /* save return address */
push $149
call syscall
add $4, %esp
push %edx
ret

.text
.type mlock, @function
.globl mlock
.align 4
mlock:
pop %edx /* save return address */
push $150
call syscall
add $4, %esp
push %edx
ret

.text
.type munlock, @function
.globl munlock
.align 4
munlock:
pop %edx /* save return address */
push $151
call syscall
add $4, %esp
push %edx
ret

.text
.type mlockall, @function
.globl mlockall
.align 4
mlockall:
pop %edx /* save return address */
push $152
call syscall
add $4, %esp
push %edx
ret

.text
.type munlockall, @function
.globl munlockall
.align 4
munlockall:
pop %edx /* save return address */
push $153
call syscall
add $4, %esp
push %edx
ret

.text
.type sched_setparam, @function
.globl sched_setparam
.align 4
sched_setparam:
pop %edx /* save return address */
push $154
call syscall
add $4, %esp
push %edx
ret

.text
.type sched_getparam, @function
.globl sched_getparam
.align 4
sched_getparam:
pop %edx /* save return address */
push $155
call syscall
add $4, %esp
push %edx
ret

.text
.type sched_setscheduler, @function
.globl sched_setscheduler
.align 4
sched_setscheduler:
pop %edx /* save return address */
push $156
call syscall
add $4, %esp
push %edx
ret

.text
.type sched_getscheduler, @function
.globl sched_getscheduler
.align 4
sched_getscheduler:
pop %edx /* save return address */
push $157
call syscall
add $4, %esp
push %edx
ret

.text
.type sched_yield, @function
.globl sched_yield
.align 4
sched_yield:
pop %edx /* save return address */
push $158
call syscall
add $4, %esp
push %edx
ret

.text
.type sched_get_priority_max, @function
.globl sched_get_priority_max
.align 4
sched_get_priority_max:
pop %edx /* save return address */
push $159
call syscall
add $4, %esp
push %edx
ret

.text
.type sched_get_priority_min, @function
.globl sched_get_priority_min
.align 4
sched_get_priority_min:
pop %edx /* save return address */
push $160
call syscall
add $4, %esp
push %edx
ret

.text
.type sched_rr_get_interval, @function
.globl sched_rr_get_interval
.align 4
sched_rr_get_interval:
pop %edx /* save return address */
push $161
call syscall
add $4, %esp
push %edx
ret

.text
.type nanosleep, @function
.globl nanosleep
.align 4
nanosleep:
pop %edx /* save return address */
push $162
call syscall
add $4, %esp
push %edx
ret

.text
.type mremap, @function
.globl mremap
.align 4
mremap:
pop %edx /* save return address */
push $163
call syscall
add $4, %esp
push %edx
ret

.text
.type setresuid, @function
.globl setresuid
.align 4
setresuid:
pop %edx /* save return address */
push $164
call syscall
add $4, %esp
push %edx
ret

.text
.type getresuid, @function
.globl getresuid
.align 4
getresuid:
pop %edx /* save return address */
push $165
call syscall
add $4, %esp
push %edx
ret

.text
.type vm86, @function
.globl vm86
.align 4
vm86:
pop %edx /* save return address */
push $166
call syscall
add $4, %esp
push %edx
ret

.text
.type query_module, @function
.globl query_module
.align 4
query_module:
pop %edx /* save return address */
push $167
call syscall
add $4, %esp
push %edx
ret

.text
.type poll, @function
.globl poll
.align 4
poll:
pop %edx /* save return address */
push $168
call syscall
add $4, %esp
push %edx
ret

.text
.type nfsservctl, @function
.globl nfsservctl
.align 4
nfsservctl:
pop %edx /* save return address */
push $169
call syscall
add $4, %esp
push %edx
ret

.text
.type setresgid, @function
.globl setresgid
.align 4
setresgid:
pop %edx /* save return address */
push $170
call syscall
add $4, %esp
push %edx
ret

.text
.type getresgid, @function
.globl getresgid
.align 4
getresgid:
pop %edx /* save return address */
push $171
call syscall
add $4, %esp
push %edx
ret

.text
.type prctl, @function
.globl prctl
.align 4
prctl:
pop %edx /* save return address */
push $172
call syscall
add $4, %esp
push %edx
ret

.text
.type rt_sigreturn, @function
.globl rt_sigreturn
.align 4
rt_sigreturn:
pop %edx /* save return address */
push $173
call syscall
add $4, %esp
push %edx
ret

.text
.type rt_sigaction, @function
.globl rt_sigaction
.align 4
rt_sigaction:
pop %edx /* save return address */
push $174
call syscall
add $4, %esp
push %edx
ret

.text
.type rt_sigprocmask, @function
.globl rt_sigprocmask
.align 4
rt_sigprocmask:
pop %edx /* save return address */
push $175
call syscall
add $4, %esp
push %edx
ret

.text
.type rt_sigpending, @function
.globl rt_sigpending
.align 4
rt_sigpending:
pop %edx /* save return address */
push $176
call syscall
add $4, %esp
push %edx
ret

.text
.type rt_sigtimedwait, @function
.globl rt_sigtimedwait
.align 4
rt_sigtimedwait:
pop %edx /* save return address */
push $177
call syscall
add $4, %esp
push %edx
ret

.text
.type rt_sigqueueinfo, @function
.globl rt_sigqueueinfo
.align 4
rt_sigqueueinfo:
pop %edx /* save return address */
push $178
call syscall
add $4, %esp
push %edx
ret

.text
.type rt_sigsuspend, @function
.globl rt_sigsuspend
.align 4
rt_sigsuspend:
pop %edx /* save return address */
push $179
call syscall
add $4, %esp
push %edx
ret

.text
.type pread, @function
.globl pread
.align 4
pread:
pop %edx /* save return address */
push $180
call syscall
add $4, %esp
push %edx
ret

.text
.type pwrite, @function
.globl pwrite
.align 4
pwrite:
pop %edx /* save return address */
push $181
call syscall
add $4, %esp
push %edx
ret

.text
.type chown, @function
.globl chown
.align 4
chown:
pop %edx /* save return address */
push $182
call syscall
add $4, %esp
push %edx
ret

.text
.type getcwd, @function
.globl getcwd
.align 4
getcwd:
pop %edx /* save return address */
push $183
call syscall
add $4, %esp
push %edx
ret

.text
.type capget, @function
.globl capget
.align 4
capget:
pop %edx /* save return address */
push $184
call syscall
add $4, %esp
push %edx
ret

.text
.type capset, @function
.globl capset
.align 4
capset:
pop %edx /* save return address */
push $185
call syscall
add $4, %esp
push %edx
ret

.text
.type sigaltstack, @function
.globl sigaltstack
.align 4
sigaltstack:
pop %edx /* save return address */
push $186
call syscall
add $4, %esp
push %edx
ret

.text
.type sendfile, @function
.globl sendfile
.align 4
sendfile:
pop %edx /* save return address */
push $187
call syscall
add $4, %esp
push %edx
ret

.text
.type getpmsg, @function
.globl getpmsg
.align 4
getpmsg:
pop %edx /* save return address */
push $188
call syscall
add $4, %esp
push %edx
ret

.text
.type putpmsg, @function
.globl putpmsg
.align 4
putpmsg:
pop %edx /* save return address */
push $189
call syscall
add $4, %esp
push %edx
ret

.text
.type vfork, @function
.globl vfork
.align 4
vfork:
pop %edx /* save return address */
push $190
call syscall
add $4, %esp
push %edx
ret

.text
.type getrlimit, @function
.globl getrlimit
.align 4
getrlimit:
pop %edx /* save return address */
push $191
call syscall
add $4, %esp
push %edx
ret

.text
.type mmap, @function
.globl mmap
.align 4
mmap:
pop %edx /* save return address */
push $192
call syscall
add $4, %esp
push %edx
ret

.text
.type set_thread_area, @function
.globl set_thread_area
.align 4
set_thread_area:
pop %edx /* save return address */
push $243
call syscall
add $4, %esp
push %edx
ret

