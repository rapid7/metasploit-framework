#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/os/main'

module Metasm
class PTrace
  attr_accessor :buf, :pid

  def self.open(target)
    ptrace = new(target)
    return ptrace if not block_given?
    ret = yield ptrace
    ptrace.detach
    ret
  end

  # calls PTRACE_TRACEME on the current (ruby) process
  def self.traceme
    new(::Process.pid, false).traceme
  end

  # creates a ptraced process (target = path)
  # or opens a running process (target = pid)
  # values for do_attach:
  #  :create => always fork+traceme+exec+wait
  #  :attach => always attach
  #  false/nil => same as attach, without actually calling PT_ATTACH (usefull if we're already tracing pid)
  #  anything else: try to attach if pid is numeric (using Integer()), else create
  def initialize(target, do_attach=true)
    begin
      raise ArgumentError if do_attach == :create
      @pid = Integer(target)
      tweak_for_pid(@pid)
      return if not do_attach
      attach
    rescue ArgumentError, TypeError
      raise if do_attach == :attach or not do_attach
      did_exec = true
      if not @pid = fork
        tweak_for_pid(::Process.pid)
        traceme
        ::Process.exec(*target)
        exit!(0)
      end
    end
    wait
    raise "could not exec #{target}" if $?.exited?
    tweak_for_pid(@pid) if did_exec
    puts "Ptrace: attached to #@pid" if $DEBUG
  end

  def wait
    ::Process.wait(@pid, ::Process::WALL)
  end

  attr_accessor :reg_off, :intsize, :syscallnr, :syscallreg
  attr_accessor :packint, :packuint, :host_intsize, :host_syscallnr
  # setup the variables according to the target
  def tweak_for_pid(pid=@pid)
    # use these for our syscalls PTRACE
    case LinOS.open_process(::Process.pid).cpu.shortname
    when 'ia32'
      @packint = 'l'
      @packuint = 'L'
      @host_intsize = 4
      @host_syscallnr = SYSCALLNR_I386
      @reg_off = REGS_I386
    when 'x64'
      @packint = 'q'
      @packuint = 'Q'
      @host_intsize = 8
      @host_syscallnr = SYSCALLNR_X86_64
      @reg_off = REGS_X86_64
    else raise 'unsupported architecture'
    end

    # use these to interpret the child state
    tgcpu = LinOS.open_process(pid).cpu
    case tgcpu.shortname
    when 'ia32'
      @syscallreg = 'ORIG_EAX'
      @syscallnr = SYSCALLNR_I386
      @intsize = 4
    when 'x64'
      @syscallreg = 'ORIG_RAX'
      @syscallnr = SYSCALLNR_X86_64
      @intsize = 8
    else raise 'unsupported target architecture'
    end

    cp = tgcpu.new_cparser
    cp.parse SIGINFO_C
    @siginfo = cp.alloc_c_struct('siginfo')

    # buffer used in ptrace syscalls
    @buf = [0].pack(@packint)
    @bufptr = str_ptr(@buf)
  end

  def str_ptr(str)
    [str].pack('P').unpack(@packint).first
  end

  # interpret the value turned as an unsigned long
  def bufval
    @buf.unpack(@packint).first
  end

  # reads a memory range
  def readmem(off, len)
    decal = off % @host_intsize
    buf = ''
    if decal > 0
      off -= decal
      peekdata(off)
      off += @host_intsize
      buf << @buf[decal...@host_intsize]
    end
    offend = off + len
    while off < offend
      peekdata(off)
      buf << @buf[0, @host_intsize]
      off += @host_intsize
    end
    buf[0, len]
  end

  def writemem(off, str)
    decal = off % @host_intsize
    if decal > 0
      off -= decal
      peekdata(off)
      str = @buf[0...decal] + str
    end
    decal = str.length % @host_intsize
    if decal > 0
      peekdata(off+str.length-decal)
      str += @buf[decal...@host_intsize]
    end
    i = 0
    while i < str.length
      pokedata(off+i, str[i, @host_intsize])
      i += @host_intsize
    end
  end

  # linux/ptrace.h
  COMMAND = {
    'TRACEME'         =>   0, 'PEEKTEXT'        =>   1,
    'PEEKDATA'        =>   2, 'PEEKUSR'         =>   3,
    'POKETEXT'        =>   4, 'POKEDATA'        =>   5,
    'POKEUSR'         =>   6, 'CONT'            =>   7,
    'KILL'            =>   8, 'SINGLESTEP'      =>   9,
    'ATTACH'          =>  16, 'DETACH'          =>  17,
    'SYSCALL'         =>  24,

    # arch/x86/include/ptrace-abi.h
    'GETREGS'         =>  12, 'SETREGS'         =>  13,
    'GETFPREGS'       =>  14, 'SETFPREGS'       =>  15,
    'GETFPXREGS'      =>  18, 'SETFPXREGS'      =>  19,
    'OLDSETOPTIONS'   =>  21, 'GET_THREAD_AREA' =>  25,
    'SET_THREAD_AREA' =>  26, 'ARCH_PRCTL'      =>  30,
    'SYSEMU'          =>  31, 'SYSEMU_SINGLESTEP'=> 32,
    'SINGLEBLOCK'     =>  33,
    # 0x4200-0x4300 are reserved for architecture-independent additions.
    'SETOPTIONS'      => 0x4200, 'GETEVENTMSG'   => 0x4201,
    'GETSIGINFO'      => 0x4202, 'SETSIGINFO'    => 0x4203
  }

  OPTIONS = {
    # options set using PTRACE_SETOPTIONS
    'TRACESYSGOOD'  => 0x01, 'TRACEFORK'     => 0x02,
    'TRACEVFORK'    => 0x04, 'TRACECLONE'    => 0x08,
    'TRACEEXEC'     => 0x10, 'TRACEVFORKDONE'=> 0x20,
    'TRACEEXIT'     => 0x40
  }

  WAIT_EXTENDEDRESULT = {
    # Wait extended result codes for the above trace options.
    'EVENT_FORK'       => 1, 'EVENT_VFORK'      => 2,
    'EVENT_CLONE'      => 3, 'EVENT_EXEC'       => 4,
    'EVENT_VFORK_DONE' => 5, 'EVENT_EXIT'       => 6
  }
  WAIT_EXTENDEDRESULT.update WAIT_EXTENDEDRESULT.invert


  # block trace
  BTS_O = { 'TRACE' => 1, 'SCHED' => 2, 'SIGNAL' => 4, 'ALLOC' => 8 }
  BTS = { 'CONFIG' => 40, 'STATUS' => 41, 'SIZE' => 42,
    'GET' => 43, 'CLEAR' => 44, 'DRAIN' => 45 }

  REGS_I386 = {
    'EBX' => 0, 'ECX' => 1, 'EDX' => 2, 'ESI' => 3,
    'EDI' => 4, 'EBP' => 5, 'EAX' => 6, 'DS'  => 7,
    'ES'  => 8, 'FS'  => 9, 'GS'  => 10, 'ORIG_EAX' => 11,
    'EIP' => 12, 'CS'  => 13, 'EFL' => 14, 'UESP'=> 15,
    'EFLAGS' => 14, 'ESP' => 15,
    'SS'  => 16,
    # from ptrace.c in kernel source & asm-i386/user.h
    'DR0' => 63, 'DR1' => 64, 'DR2' => 65, 'DR3' => 66,
    'DR4' => 67, 'DR5' => 68, 'DR6' => 69, 'DR7' => 70
  }

  REGS_X86_64 = {
    'R15' => 0, 'R14' => 1, 'R13' => 2, 'R12' => 3,
    'RBP' => 4, 'RBX' => 5, 'R11' => 6, 'R10' => 7,
    'R9' => 8, 'R8' => 9, 'RAX' => 10, 'RCX' => 11,
    'RDX' => 12, 'RSI' => 13, 'RDI' => 14, 'ORIG_RAX' => 15,
    'RIP' => 16, 'CS' => 17, 'RFLAGS' => 18, 'RSP' => 19,
    'SS' => 20, 'FS_BASE' => 21, 'GS_BASE' => 22, 'DS' => 23,
    'ES' => 24, 'FS' => 25, 'GS' => 26,
    #'FP_VALID' => 27,
    #'387_XWD' => 28, '387_RIP' => 29, '387_RDP' => 30, '387_MXCSR' => 31,
    #'FP0' => 32, 'FP1' => 34, 'FP2' => 36, 'FP3' => 38,
    #'FP4' => 40, 'FP5' => 42, 'FP6' => 44, 'FP7' => 46,
    #'XMM0' => 48, 'XMM1' => 52, 'XMM2' => 56, 'XMM3' => 60,
    #'XMM4' => 64, 'XMM5' => 68, 'XMM6' => 72, 'XMM7' => 76,
    #'FPAD0' => 80, 'FPAD11' => 91,
    #'TSZ' => 92, 'DSZ' => 93, 'SSZ' => 94, 'CODE' => 95,
    #'STK' => 96, 'SIG' => 97, 'PAD' => 98, 'U_AR0' => 99,
    #'FPPTR' => 100, 'MAGIC' => 101, 'COMM0' => 102, 'COMM1' => 103,
    #'COMM2' => 104, 'COMM3' => 105,
    'DR0' => 106, 'DR1' => 107, 'DR2' => 108, 'DR3' => 109,
    'DR4' => 110, 'DR5' => 111, 'DR6' => 112, 'DR7' => 113,
    #'ERROR_CODE' => 114, 'FAULT_ADDR' => 115
  }

  SYSCALLNR_I386 = %w[restart_syscall exit fork read write open close waitpid creat link unlink execve chdir time
    mknod chmod lchown break oldstat lseek getpid mount umount setuid getuid stime ptrace alarm oldfstat
    pause utime stty gtty access nice ftime sync kill  rename mkdir rmdir dup pipe times prof brk setgid
    getgid signal  geteuid getegid acct  umount2 lock ioctl fcntl  mpx setpgid ulimit  oldolduname umask
    chroot ustat  dup2 getppid getpgrp setsid  sigaction sgetmask ssetmask setreuid  setregid sigsuspend
    sigpending sethostname  setrlimit getrlimit getrusage gettimeofday  settimeofday getgroups setgroups
    select symlink oldlstat readlink uselib swapon  reboot readdir mmap munmap truncate ftruncate fchmod
    fchown getpriority  setpriority profil statfs  fstatfs ioperm socketcall syslog  setitimer getitimer
    stat  lstat fstat  olduname iopl  vhangup idle  vm86old wait4  swapoff sysinfo  ipc fsync  sigreturn
    clone  setdomainname  uname  modify_ldt  adjtimex  mprotect  sigprocmask  create_module  init_module
    delete_module get_kernel_syms quotactl getpgid fchdir bdflush sysfs personality afs_syscall setfsuid
    setfsgid  _llseek getdents  _newselect  flock  msync readv  writev  getsid  fdatasync _sysctl  mlock
    munlock  mlockall  munlockall  sched_setparam sched_getparam  sched_setscheduler  sched_getscheduler
    sched_yield  sched_get_priority_max  sched_get_priority_min sched_rr_get_interval  nanosleep  mremap
    setresuid  getresuid  vm86  query_module  poll nfsservctl  setresgid  getresgid  prctl  rt_sigreturn
    rt_sigaction  rt_sigprocmask  rt_sigpending  rt_sigtimedwait rt_sigqueueinfo  rt_sigsuspend  pread64
    pwrite64 chown  getcwd capget  capset sigaltstack  sendfile getpmsg  putpmsg vfork  ugetrlimit mmap2
    truncate64  ftruncate64  stat64  lstat64  fstat64 lchown32  getuid32  getgid32  geteuid32  getegid32
    setreuid32  setregid32   getgroups32  setgroups32   fchown32  setresuid32   getresuid32  setresgid32
    getresgid32 chown32  setuid32 setgid32 setfsuid32  setfsgid32 pivot_root mincore  madvise getdents64
    fcntl64 sys_222 sys_223  gettid readahead setxattr lsetxattr fsetxattr  getxattr lgetxattr fgetxattr
    listxattr  llistxattr  flistxattr  removexattr  lremovexattr  fremovexattr  tkill  sendfile64  futex
    sched_setaffinity sched_getaffinity set_thread_area get_thread_area io_setup io_destroy io_getevents
    io_submit io_cancel  fadvise64 sys_251  exit_group lookup_dcookie epoll_create  epoll_ctl epoll_wait
    remap_file_pages   set_tid_address   timer_create   timer_settime   timer_gettime   timer_getoverrun
    timer_delete  clock_settime clock_gettime  clock_getres  clock_nanosleep  statfs64 fstatfs64  tgkill
    utimes  fadvise64_64  vserver  mbind  get_mempolicy  set_mempolicy  mq_open  mq_unlink  mq_timedsend
    mq_timedreceive mq_notify mq_getsetattr kexec_load  waitid sys_setaltroot add_key request_key keyctl
    ioprio_set ioprio_get  inotify_init inotify_add_watch inotify_rm_watch migrate_pages  openat mkdirat
    mknodat  fchownat  futimesat  fstatat64  unlinkat  renameat  linkat  symlinkat  readlinkat  fchmodat
    faccessat pselect6 ppoll unshare set_robust_list get_robust_list splice sync_file_range tee vmsplice
    move_pages   getcpu  epoll_pwait  utimensat   signalfd  timerfd  eventfd  fallocate  timerfd_settime
           timerfd_gettime  signalfd4   eventfd2  epoll_create1   dup3   pipe2  inotify_init1   preadv  pwritev
    rt_tg_sigqueueinfo perf_counter_open].inject({}) { |h, sc| h.update sc => h.length }
  SYSCALLNR_I386.update SYSCALLNR_I386.invert
  
  SYSCALLNR_X86_64 = %w[read write open close stat fstat lstat poll lseek mmap mprotect munmap brk rt_sigaction
    rt_sigprocmask  rt_sigreturn ioctl  pread64 pwrite64  readv  writev access  pipe select  sched_yield
    mremap  msync  mincore  madvise  shmget  shmat  shmctl dup  dup2  pause  nanosleep  getitimer  alarm
    setitimer  getpid  sendfile   socket  connect  accept  sendto  recvfrom   sendmsg  recvmsg  shutdown
    bind  listen  getsockname getpeername  socketpair  setsockopt  getsockopt  clone fork  vfork  execve
    exit  wait4  kill  uname  semget  semop  semctl  shmdt  msgget  msgsnd  msgrcv  msgctl  fcntl  flock
    fsync  fdatasync  truncate  ftruncate  getdents  getcwd   chdir  fchdir  rename  mkdir  rmdir  creat
    link  unlink  symlink  readlink  chmod  fchmod chown  fchown  lchown  umask  gettimeofday  getrlimit
    getrusage  sysinfo  times  ptrace  getuid  syslog  getgid  setuid  setgid  geteuid  getegid  setpgid
    getppid  getpgrp  setsid  setreuid  setregid   getgroups  setgroups  setresuid  getresuid  setresgid
    getresgid   getpgid   setfsuid  setfsgid   getsid   capget   capset  rt_sigpending   rt_sigtimedwait
    rt_sigqueueinfo  rt_sigsuspend  sigaltstack utime  mknod  uselib  personality ustat  statfs  fstatfs
    sysfs  getpriority setpriority  sched_setparam sched_getparam  sched_setscheduler sched_getscheduler
    sched_get_priority_max   sched_get_priority_min   sched_rr_get_interval   mlock   munlock   mlockall
    munlockall vhangup  modify_ldt pivot_root  _sysctl prctl arch_prctl  adjtimex setrlimit  chroot sync
    acct  settimeofday  mount  umount2  swapon  swapoff reboot  sethostname  setdomainname  iopl  ioperm
    create_module  init_module delete_module  get_kernel_syms query_module  quotactl nfsservctl  getpmsg
    putpmsg  afs_syscall  tuxcall  security  gettid  readahead  setxattr  lsetxattr  fsetxattr  getxattr
    lgetxattr fgetxattr listxattr llistxattr flistxattr removexattr lremovexattr fremovexattr tkill time
    futex sched_setaffinity sched_getaffinity set_thread_area io_setup io_destroy io_getevents io_submit
    io_cancel get_thread_area lookup_dcookie  epoll_create epoll_ctl_old epoll_wait_old remap_file_pages
    getdents64   set_tid_address  restart_syscall   semtimedop   fadvise64  timer_create   timer_settime
    timer_gettime timer_getoverrun timer_delete clock_settime clock_gettime clock_getres clock_nanosleep
    exit_group  epoll_wait epoll_ctl  tgkill utimes  vserver mbind  set_mempolicy get_mempolicy  mq_open
    mq_unlink mq_timedsend mq_timedreceive mq_notify mq_getsetattr kexec_load waitid add_key request_key
    keyctl ioprio_set  ioprio_get inotify_init  inotify_add_watch inotify_rm_watch  migrate_pages openat
    mkdirat  mknodat  fchownat  futimesat  newfstatat  unlinkat  renameat  linkat  symlinkat  readlinkat
    fchmodat faccessat pselect6 ppoll unshare set_robust_list get_robust_list splice tee sync_file_range
    vmsplice move_pages utimensat epoll_pwait  signalfd timerfd_create eventfd fallocate timerfd_settime
    timerfd_gettime accept4  signalfd4 eventfd2  epoll_create1 dup3  pipe2 inotify_init1  preadv pwritev
    rt_tgsigqueueinfo perf_counter_open].inject({}) { |h, sc| h.update sc => h.length }
  SYSCALLNR_X86_64.update SYSCALLNR_X86_64.invert

  SIGNAL = Signal.list.dup
  SIGNAL.delete SIGNAL.index(0)
  SIGNAL['TRAP'] ||= 5	# windows+gdbremote
  SIGNAL.update SIGNAL.invert

  # include/asm-generic/errno-base.h
  ERRNO = %w[ERR0 EPERM ENOENT ESRCH EINTR EIO ENXIO E2BIG ENOEXEC EBADF ECHILD EAGAIN ENOMEM EACCES EFAULT
    ENOTBLK EBUSY EEXIST EXDEV ENODEV ENOTDIR EISDIR EINVAL ENFILE EMFILE ENOTTY ETXTBSY EFBIG ENOSPC
    ESPIPE EROFS EMLINK EPIPE EDOM ERANGE].inject({}) { |h, e| h.update e => h.length }
  ERRNO.update ERRNO.invert

  SIGINFO = {
    # user-generated signal
    'DETHREAD' => -7,	# execve killing threads
    'TKILL' => -6, 'SIGIO' => -5, 'ASYNCIO' => -4, 'MESGQ' => -3,
    'TIMER' => -2, 'QUEUE' => -1, 'USER' => 0, 'KERNEL' => 0x80,
    # ILL
    'ILLOPC' => 1, 'ILLOPN' => 2, 'ILLADR' => 3, 'ILLTRP' => 4,
    'PRVOPC' => 5, 'PRVREG' => 6, 'COPROC' => 7, 'BADSTK' => 8,
    # FPE
    'INTDIV' => 1, 'INTOVF' => 2, 'FLTDIV' => 3, 'FLTOVF' => 4,
    'FLTUND' => 5, 'FLTRES' => 6, 'FLTINV' => 7, 'FLTSUB' => 8,
    # SEGV
    'MAPERR' => 1, 'ACCERR' => 2,
    # BUS
    'ADRALN' => 1, 'ADRERR' => 2, 'OBJERR' => 3, 'MCEERR_AR' => 4,
    'MCEERR_AO' => 5,
    # TRAP
    'BRKPT' => 1, 'TRACE' => 2, 'BRANCH' => 3, 'HWBKPT' => 4,
    # CHLD
    'EXITED' => 1, 'KILLED' => 2, 'DUMPED' => 3, 'TRAPPED' => 4,
    'STOPPED' => 5, 'CONTINUED' => 6,
    # POLL
    'POLL_IN' => 1, 'POLL_OUT' => 2, 'POLL_MSG' => 3, 'POLL_ERR' => 4,
    'POLL_PRI' => 5, 'POLL_HUP' => 6
  }

  SIGINFO_C = <<EOS
typedef __int32 __pid_t;
typedef unsigned __int32 __uid_t;
typedef uintptr_t sigval_t;
typedef long __clock_t;

typedef struct siginfo {
    int si_signo;
    int si_errno;
    int si_code;
    // int pad64;
    union {
        int _pad[128/4-3];	/* total >= 128b */

        struct {		/* kill().  */
            __pid_t si_pid;	/* Sending process ID.  */
            __uid_t si_uid;	/* Real user ID of sending process.  */
        } _kill;
        struct {		/* POSIX.1b timers.  */
            int si_tid;		/* Timer ID.  */
            int si_overrun;	/* Overrun count.  */
            sigval_t si_sigval;	/* Signal value.  */
        } _timer;
        struct {		/* POSIX.1b signals.  */
            __pid_t si_pid;	/* Sending process ID.  */
            __uid_t si_uid;	/* Real user ID of sending process.  */
            sigval_t si_sigval;	/* Signal value.  */
        } _rt;
        struct {		/* SIGCHLD.  */
            __pid_t si_pid;	/* Which child.  */
            __uid_t si_uid;	/* Real user ID of sending process.  */
            int si_status;	/* Exit value or signal.  */
            __clock_t si_utime;
            __clock_t si_stime;
        } _sigchld;
        struct {		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS.  */
            uintptr_t si_addr;	/* Faulting insn/memory ref.  */
        } _sigfault;
        struct {		/* SIGPOLL.  */
            long int si_band;	/* Band event for SIGPOLL.  */
            int si_fd;
        } _sigpoll;
    };
} siginfo_t;
EOS

  def sys_ptrace(req, pid, addr, data)
    data = str_ptr(data) if data.kind_of?(String)
    addr = [addr].pack(@packint).unpack(@packint).first
    data = [data].pack(@packint).unpack(@packint).first
    Kernel.syscall(@host_syscallnr['ptrace'], req, pid, addr, data)
  end

  def traceme
    sys_ptrace(COMMAND['TRACEME'],  0, 0, 0)
  end

  def peektext(addr)
    sys_ptrace(COMMAND['PEEKTEXT'], @pid, addr, @bufptr)
    @buf
  end

  def peekdata(addr)
    sys_ptrace(COMMAND['PEEKDATA'], @pid, addr, @bufptr)
    @buf
  end

  def peekusr(addr)
    sys_ptrace(COMMAND['PEEKUSR'],  @pid, @host_intsize*addr, @bufptr)
    bufval & ((1 << ([@host_intsize, @intsize].min*8)) - 1)
  end

  def poketext(addr, data)
    sys_ptrace(COMMAND['POKETEXT'], @pid, addr, data.unpack(@packint).first)
  end

  def pokedata(addr, data)
    sys_ptrace(COMMAND['POKEDATA'], @pid, addr, data.unpack(@packint).first)
  end

  def pokeusr(addr, data)
    sys_ptrace(COMMAND['POKEUSR'],  @pid, @host_intsize*addr, data)
  end

  def getregs(buf=nil)
    buf ||= [0].pack('C')*512
    sys_ptrace(COMMAND['GETREGS'], @pid, 0, buf)
    buf
  end
  def setregs(buf)
    sys_ptrace(COMMAND['SETREGS'], @pid, 0, buf)
  end

  def getfpregs(buf=nil)
    buf ||= [0].pack('C')*1024
    sys_ptrace(COMMAND['GETFPREGS'], @pid, 0, buf)
    buf
  end
  def setfpregs(buf)
    sys_ptrace(COMMAND['SETFPREGS'], @pid, 0, buf)
  end

  def getfpxregs(buf=nil)
    buf ||= [0].pack('C')*512
    sys_ptrace(COMMAND['GETFPXREGS'], @pid, 0, buf)
    buf
  end
  def setfpxregs(buf)
    sys_ptrace(COMMAND['SETFPXREGS'], @pid, 0, buf)
  end

  def get_thread_area(addr)
    sys_ptrace(COMMAND['GET_THREAD_AREA'],  @pid, addr, @bufptr)
    bufval
  end
  def set_thread_area(addr, data)
    sys_ptrace(COMMAND['SET_THREAD_AREA'],  @pid, addr, data)
  end

  def prctl(addr, data)
    sys_ptrace(COMMAND['ARCH_PRCTL'], @pid, addr, data)
  end
  
  def cont(sig = nil)
    sig ||= 0
    sys_ptrace(COMMAND['CONT'], @pid, 0, sig)
  end

  def kill
    sys_ptrace(COMMAND['KILL'], @pid, 0, 0)
  end

  def singlestep(sig = nil)
    sig ||= 0
    sys_ptrace(COMMAND['SINGLESTEP'], @pid, 0, sig)
  end

  def singleblock(sig = nil)
    sig ||= 0
    sys_ptrace(COMMAND['SINGLEBLOCK'], @pid, 0, sig)
  end

  def syscall(sig = nil)
    sig ||= 0
    sys_ptrace(COMMAND['SYSCALL'], @pid, 0, sig)
  end

  def attach
    sys_ptrace(COMMAND['ATTACH'], @pid, 0, 0)
  end

  def detach
    sys_ptrace(COMMAND['DETACH'], @pid, 0, 0)
  end

  def setoptions(*opt)
    opt = opt.inject(0) { |b, o| b |= o.kind_of?(Integer) ? o : OPTIONS[o] }
    sys_ptrace(COMMAND['SETOPTIONS'], @pid, 0, opt)
  end

  # retrieve pid of cld for EVENT_CLONE/FORK, exitcode for EVENT_EXIT
  def geteventmsg
    sys_ptrace(COMMAND['GETEVENTMSG'], @pid, 0, @bufptr)
    bufval
  end

  def getsiginfo
    sys_ptrace(COMMAND['GETSIGINFO'], @pid, 0, @siginfo.str)
    @siginfo
  end

  def setsiginfo(si=@siginfo)
    si = si.str if si.respond_to?(:str)
    sys_ptrace(COMMAND['SETSIGINFO'], @pid, 0, si)
  end
end

class LinOS < OS
  class Process < OS::Process
    # returns/create a LinuxRemoteString
    def memory
      @memory ||= LinuxRemoteString.new(pid)
    end
    attr_writer :memory

    def debugger
      @debugger ||= LinDebugger.new(@pid)
    end
    attr_writer :debugger

    # returns the list of loaded Modules, incl start address & path
    # read from /proc/pid/maps
    def modules
      list = []
      seen = {}
      File.readlines("/proc/#{pid}/maps").each { |l|
        # 08048000-08064000 r-xp 000000 08:01 4234 /usr/bin/true
        l = l.split
        next if l.length < 6 or seen[l[-1]]
        seen[l[-1]] = true
        m = Module.new
        m.addr = l[0].to_i(16)
        m.path = l[-1]
        list << m
      }
      list
    rescue
      []
    end

    # return a list of [addr_start, length, perms, file]
    def mappings
      list = []
      File.readlines("/proc/#{pid}/maps").each { |l|
        l = l.split
        addrstart, addrend = l[0].split('-').map { |i| i.to_i 16 }
        list << [addrstart, addrend-addrstart, l[1], l[5]]
      }
      list
    rescue
      []
    end

    # returns a list of threads sharing this process address space
    # read from /proc/pid/task/
    def threads
      Dir.entries("/proc/#{pid}/task/").grep(/^\d+$/).map { |tid| tid.to_i }
           rescue
      # TODO handle pthread stuff (eg 2.4 kernels)
      [pid]
    end

    # return the invocation commandline, from /proc/pid/cmdline
    # this is manipulable by the target itself
    def cmdline
      @cmdline ||= File.read("/proc/#{pid}/cmdline") rescue ''
    end
    attr_writer :cmdline

    def path
      cmdline.split(0.chr)[0]
    end

    # returns the address size of the process, based on its #cpu
    def addrsz
      cpu.size
    end

    # returns the CPU for the process, by reading /proc/pid/exe
    def cpu
      e = ELF.load_file("/proc/#{pid}/exe")
      # dont decode shdr/phdr, this is 2x faster for repeated debugger spawn
      e.decode_header(0, false, false)
      e.cpu
    end

    def terminate
      kill
  end

    def kill(signr=9)
      ::Process.kill(signr, @pid)
    end
  end

class << self
  # returns an array of Processes, with pid/module listing
  def list_processes
    Dir.entries('/proc').grep(/^\d+$/).map { |pid| Process.new(pid.to_i) }
  end

  # return a Process for the specified pid if it exists in /proc
  def open_process(pid)
    Process.new(pid) if check_process(pid)
  end

  def check_process(pid)
    File.directory?("/proc/#{pid}")
  end

  # create a LinDebugger on the target pid/binary
  def create_debugger(path)
    LinDebugger.new(path)
  end
end	# class << self
end

class LinuxRemoteString < VirtualString
  attr_accessor :pid, :readfd
  attr_accessor :dbg

  # returns a virtual string proxying the specified process memory range
  # reads are cached (4096 aligned bytes read at once), from /proc/pid/mem
  # writes are done directly by ptrace
  def initialize(pid, addr_start=0, length=nil, dbg=nil)
    @pid = pid
    length ||= 1 << (dbg ? dbg.cpu.size : (LinOS.open_process(@pid).addrsz rescue 32))
    @readfd = File.open("/proc/#@pid/mem", 'rb') rescue nil
    @dbg = dbg if dbg
    super(addr_start, length)
  end

  def dup(addr = @addr_start, len = @length)
    self.class.new(@pid, addr, len, dbg)
  end

  def do_ptrace
    if dbg
      dbg.switch_context(@pid) {
        # XXX tid ?
        yield dbg.ptrace if dbg.state == :stopped
      }
    else
      PTrace.open(@pid) { |ptrace| yield ptrace }
    end
  end

  def rewrite_at(addr, data)
    # target must be stopped
    do_ptrace { |ptrace| ptrace.writemem(addr, data) }
  end

  def get_page(addr, len=@pagelength)
    do_ptrace { |ptrace|
      begin
        if readfd and addr < (1<<63)
          # 1<<63: ruby seek = 'too big to fit longlong', linux read = EINVAL
          @readfd.pos = addr
          @readfd.read len
        elsif addr < (1<<(ptrace.host_intsize*8))
          # can reach 1<<64 with peek_data only if ptrace accepts 64bit args
          ptrace.readmem(addr, len)
        end
      rescue Errno::EIO, Errno::ESRCH
        nil
      end
    }
  end
end

module ::Process
  WALL   = 0x40000000 if not defined? WALL
  WCLONE = 0x80000000 if not defined? WCLONE
end

# this class implements a high-level API over the ptrace debugging primitives
class LinDebugger < Debugger
  # ptrace is per-process or per-thread ?
  attr_accessor :ptrace, :continuesignal, :has_pax_mprotect, :target_syscall
  attr_accessor :callback_syscall, :callback_branch, :callback_exec

  def initialize(pidpath=nil)
    super()
    @pid_stuff_list << :has_pax_mprotect << :ptrace	<< :breaking << :os_process
    @tid_stuff_list << :continuesignal << :saved_csig << :ctx << :target_syscall

    # by default, break on all signals except SIGWINCH (terminal resize notification)
    @pass_all_exceptions = lambda { |e| e[:signal] == 'WINCH' }

    @callback_syscall = lambda { |i| log "syscall #{i[:syscall]}" }
    @callback_exec = lambda { |i| log "execve #{os_process.path}" }

    return if not pidpath

    begin
      pid = Integer(pidpath)
      attach(pid)
    rescue ArgumentError
      create_process(pidpath)
    end
  end

  def shortname; 'lindbg'; end

  # attach to a running process and all its threads
  def attach(pid, do_attach=:attach)
    pt = PTrace.new(pid, do_attach)
    set_context(pt.pid, pt.pid)	# swapout+init_newpid
    log "attached #@pid"
    list_threads.each { |tid| attach_thread(tid) if tid != @pid }
  end

  # create a process and debug it
  def create_process(path)
    pt = PTrace.new(path, :create)
    # TODO save path, allow restart etc
    set_context(pt.pid, pt.pid)	# swapout+init_newpid
    log "attached #@pid"
  end

  def initialize_cpu
    @cpu = os_process.cpu
    # need to init @ptrace here, before init_dasm calls gui.swapin
    @ptrace = PTrace.new(@pid, false)
    if @cpu.size == 64 and @ptrace.reg_off['EAX']
      hack_64_32
    end
    set_tid @pid
    set_thread_options
  end

  def initialize_memory
    @memory = os_process.memory = LinuxRemoteString.new(@pid, 0, nil, self)
  end

  def os_process
    @os_process ||= LinOS.open_process(@pid)
  end

  def list_threads
    os_process.threads
  end

  def list_processes
    LinOS.list_processes
  end

  def check_pid(pid)
    LinOS.check_process(pid)
  end

  def mappings
    os_process.mappings
  end

  def modules
    os_process.modules
  end

  # we're a 32bit process debugging a 64bit target
  # the ptrace kernel interface we use only allow us a 32bit-like target access
  # with this we advertize the cpu as having eax..edi registers (the only one we
  # can access), while still decoding x64 instructions (whose addr < 4G)
  def hack_64_32
    log "WARNING: debugging a 64bit process from a 32bit debugger is a very bad idea !"
    @cpu.instance_eval {
      ia32 = Ia32.new
      @dbg_register_pc = ia32.dbg_register_pc
      @dbg_register_flags = ia32.dbg_register_flags
      @dbg_register_list = ia32.dbg_register_list
      @dbg_register_size = ia32.dbg_register_size
    }
  end

  # attach a thread of the current process
  def attach_thread(tid)
    set_tid tid
    @ptrace.pid = tid
      @ptrace.attach
    @state = :stopped	# no need to wait()
    log "attached thread #{tid}"
    set_thread_options
  end

  # set the debugee ptrace options (notify clone/exec/exit, and fork/vfork depending on @trace_children)
  def set_thread_options
    opts  = %w[TRACESYSGOOD TRACECLONE TRACEEXEC TRACEEXIT]
    opts += %w[TRACEFORK TRACEVFORK TRACEVFORKDONE] if trace_children
    @ptrace.pid = @tid
    @ptrace.setoptions(*opts)
  end

  # update the current pid relative to tracing children (@trace_children only effects newly traced pid/tid)
  def do_trace_children
    each_tid { set_thread_options }
  end

  def invalidate
    @ctx = nil
    super()
  end

  # a hash of the current thread context
  # TODO keys = :gpr, :fpu, :xmm, :dr ; val = AllocCStruct
  # include accessors for st0/xmm12 (@ptrace.getfpregs.unpack etc)
  def ctx
    @ctx ||= {}
  end

  def get_reg_value(r)
    raise "bad register #{r}" if not k = @ptrace.reg_off[r.to_s.upcase]
    return ctx[r] || 0 if @state != :stopped
    @ptrace.pid = @tid
    ctx[r] ||= @ptrace.peekusr(k)
  rescue Errno::ESRCH
    0
  end
  def set_reg_value(r, v)
    raise "bad register #{r}" if not k = @ptrace.reg_off[r.to_s.upcase]
    ctx[r] = v
    return if @state != :stopped
    @ptrace.pid = @tid
    @ptrace.pokeusr(k, v)
  end

  def update_waitpid(status)
    invalidate
    @continuesignal = 0
    @state = :stopped	# allow get_reg (for eg pt_syscall)
    info = { :status => status }
    if status.exited?
      info.update :exitcode => status.exitstatus
      if @tid == @pid		# XXX
        evt_endprocess info
      else
        evt_endthread info
      end
    elsif status.signaled?
      info.update :signal => (PTrace::SIGNAL[status.termsig] || status.termsig)
      if @tid == @pid
        evt_endprocess info
      else
        evt_endthread info
      end
    elsif status.stopped?
      sig = status.stopsig & 0x7f
      signame = PTrace::SIGNAL[sig] 
      if signame == 'TRAP'
        if status.stopsig & 0x80 > 0
          # XXX int80 in x64 => syscallnr32 ?
          evt_syscall info.update(:syscall => @ptrace.syscallnr[get_reg_value(@ptrace.syscallreg)])

        elsif (status >> 16) > 0
          case o = PTrace::WAIT_EXTENDEDRESULT[status >> 16]
          when 'EVENT_FORK', 'EVENT_VFORK'
            # parent notification of a fork
            # child receives STOP (may have already happened)
            #cld = @ptrace.geteventmsg
            resume_badbreak

          when 'EVENT_CLONE'
            #cld = @ptrace.geteventmsg
            resume_badbreak

          when 'EVENT_EXIT'
            info.update :exitcode => @ptrace.geteventmsg
            if @tid == @pid
              evt_endprocess info
            else
              evt_endthread info
            end

          when 'EVENT_VFORKDONE'
            resume_badbreak

          when 'EVENT_EXEC'
            evt_exec info
          end

        else
          si = @ptrace.getsiginfo
          case si.si_code
          when PTrace::SIGINFO['BRKPT'],
               PTrace::SIGINFO['KERNEL']	# \xCC prefer KERNEL to BRKPT
            evt_bpx
          when PTrace::SIGINFO['TRACE']
            evt_singlestep	# singlestep/singleblock
          when PTrace::SIGINFO['BRANCH']
            evt_branch	# XXX BTS?
          when PTrace::SIGINFO['HWBKPT']
            evt_hwbp
          else
            @saved_csig = @continuesignal = sig
            info.update :signal => signame, :type => "SIG#{signame}"
            evt_exception info
        end
        end

      elsif signame == 'STOP' and @info == 'new'
        # new thread break on creation (eg after fork + TRACEFORK)
        if @pid == @tid
          attach(@pid, false)
          evt_newprocess info
      else
          evt_newthread info
        end

      elsif signame == 'STOP' and @breaking
        @state = :stopped
        @info = 'break'
          @breaking = nil

        else
        @saved_csig = @continuesignal = sig
        info.update :signal => signame, :type => "SIG#{signame}"
        if signame == 'SEGV'
          # need more data on access violation (for bpm)
          info.update :type => 'access violation'
          si = @ptrace.getsiginfo
          access = case si.si_code
             when PTrace::SIGINFO['MAPERR']; :r	# XXX write access to unmapped => ?
             when PTrace::SIGINFO['ACCERR']; :w
        end
          info.update :fault_addr => si.si_addr, :fault_access => access
        end
        evt_exception info
      end
    else
      log "unknown wait status #{status.inspect}"
      evt_exception info.update(:type => "unknown wait #{status.inspect}")
    end
  end
  
  def set_tid_findpid(tid)
    return if tid == @tid
    if tid != @pid and pr = list_processes.find { |p| p.threads.include? tid }
      set_pid pr.pid
    end
    set_tid tid
  end

  def do_check_target
    return unless t = ::Process.waitpid(-1, ::Process::WNOHANG | ::Process::WALL)
    # XXX all threads may have stopped, wait them now ?
    set_tid_findpid t
    update_waitpid $?
  rescue ::Errno::ECHILD
  end

  def do_wait_target
    t = ::Process.waitpid(-1, ::Process::WALL)
    set_tid_findpid t
    update_waitpid $?
  rescue ::Errno::ECHILD
  end

  def do_continue
    @ptrace.pid = tid
    @ptrace.cont(@continuesignal)
  end

  def do_singlestep(*a)
    @ptrace.pid = tid
    @ptrace.singlestep(@continuesignal)
  end

  # use the PT_SYSCALL to break on next syscall
  # regexp allowed to wait a specific syscall
  def syscall(arg=nil)
    arg = nil if arg and arg.strip == ''
    return if not check_pre_run(:syscall, arg)
    @target_syscall = arg
    @ptrace.pid = @tid
    @ptrace.syscall(@continuesignal)
  end

  def syscall_wait(*a, &b)
    syscall(*a, &b)
    wait_target
  end

  # use the PT_SINGLEBLOCK to execute until the next branch
  def singleblock
    # record as singlestep to avoid evt_singlestep -> evt_exception
    # step or block doesn't matter much here anyway
    return if not check_pre_run(:singlestep)
    @ptrace.pid = @tid
    @ptrace.singleblock(@continuesignal)
  end

  def singleblock_wait(*a, &b)
    singleblock(*a, &b)
    wait_target
  end

  # woke up from a PT_SYSCALL
  def evt_syscall(info={})
    @state = :stopped
    @info = "syscall #{info[:syscall]}"

    callback_syscall[info] if callback_syscall

    if @target_syscall and info[:syscall] !~ /^#@target_syscall$/i
      resume_badbreak
    else
      @target_syscall = nil
    end
  end

  # SIGTRAP + SIGINFO_TRAP_BRANCH = ?
  def evt_branch(info={})
    @state = :stopped
    @info = "branch"

    callback_branch[info] if callback_branch
  end

  # called during sys_execve in the new process
  def evt_exec(info={})
    @state = :stopped
    @info = "#{info[:exec]} execve"

    initialize_newpid
    # XXX will receive a SIGTRAP, could hide it..

    callback_exec[info] if callback_exec
    # calling continue() here will loop back to TRAP+INFO_EXEC
  end

  def break
    @breaking = true
    kill 'STOP'
  end

  def kill(sig=nil)
    return if not tid
    # XXX tkill ?
    ::Process.kill(sig2signr(sig), tid)
  rescue Errno::ESRCH
  end

  def pass_current_exception(bool=true)
    if bool
      @continuesignal = @saved_csig
    else
      @continuesignal = 0
      end
      end

  def sig2signr(sig)
    case sig
    when nil, ''; 9
    when Integer; sig
    when String
             sig = sig.upcase.sub(/^SIG_?/, '')
      PTrace::SIGNAL[sig] || Integer(sig)
    else raise "unhandled signal #{sig.inspect}"
      end
  end

  # stop debugging the current process
  def detach
    del_all_breakpoints
    each_tid {
      @ptrace.pid = @tid
      @ptrace.detach
      @delete_thread = true
    }
    del_pid
  end

  def bpx(addr, *a, &b)
    return hwbp(addr, :x, 1, *a, &b) if @has_pax_mprotect
    super(addr, *a, &b)
  end

  # handles exceptions from PaX-style mprotect restrictions on bpx,
  # transmute them to hwbp on the fly
  def do_enable_bp(b)
    super(b)
  rescue ::Errno::EIO
    if b.type == :bpx
      @memory[b.address, 1]	# check if we can read
      # didn't raise: it's a PaX-style config
      @has_pax_mprotect = true
      b.del
      hwbp(b.address, :x, 1, b.oneshot, b.condition, &b.action)
      log 'PaX: bpx->hwbp'
    else raise
    end
  end

  def ui_command_setup(ui)
    ui.new_command('syscall', 'waits for the target to do a syscall using PT_SYSCALL') { |arg| ui.wrap_run { syscall arg } }
    ui.keyboard_callback[:f6] = lambda { ui.wrap_run { syscall } }

    ui.new_command('signal_cont', 'set/get the continue signal (0 == unset)') { |arg|
      case arg.to_s.strip
      when ''; log "#{@continuesignal} (#{PTrace::SIGNAL[@continuesignal]})"
      else @continuesignal = sig2signr(arg)
      end
    }
  end
end
end
