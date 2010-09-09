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

	# creates a ptraced process (target = path)
	# or opens a running process (target = pid)
	def initialize(target)
		begin
			@pid = Integer(target)
			tweak_for_pid(@pid)
			attach
		rescue ArgumentError, TypeError
			did_exec = true
			if not @pid = fork
				tweak_for_pid(::Process.pid)
				traceme
				Process.exec(*target)
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

	attr_accessor :reg_off, :intsize, :syscallnr
	# setup the variables according to the target
	# XXX when x86 debugs x64, should we use ptrace_X86_ATTACH or X64_ATTACH ?
	def tweak_for_pid(pid=@pid)
		tg = OS.current.open_process(::Process.pid)
		psz = tg.addrsz
		case psz
		when 32
			@packint = 'l'
			@packuint = 'L'
			@host_intsize = 4
			@host_syscallnr = SYSCALLNR
			@reg_off = REGS_I386
		when 64
			@packint = 'q'
			@packuint = 'Q'
			@host_intsize = 8
			@host_syscallnr = SYSCALLNR_64
			@reg_off = REGS_X86_64
		else raise 'unsupported architecture'
		end

		case OS.current.open_process(pid).addrsz
		when 32
			@syscallnr = SYSCALLNR
			@intsize = 4
		when 64
			@syscallnr = SYSCALLNR_64
			@intsize = 8
		else raise 'unsupported target architecture'
		end

		@buf = [0].pack(@packint)
		@bufptr = [@buf].pack('P').unpack(@packint).first
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

		# i486-asm/ptrace.h
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
		# fpval pad i387=29...73 tsz dsz ssz code stack sig res pad1 ar0 fps mag comm*4
		'DR0' => 88, 'DR1' => 89, 'DR2' => 90, 'DR3' => 91,
		'DR4' => 92, 'DR5' => 93, 'DR6' => 94, 'DR7' => 95,
		'ERROR_CODE' => 96, 'FAULT_ADDR' => 97
	}

#  this struct defines the way the registers are stored on the stack during a system call.
# struct pt_regs {
#        long ebx; long ecx; long edx; long esi;
#        long edi; long ebp; long eax; int  xds;
#        int  xes; long orig_eax; long eip; int  xcs;
#        long eflags; long esp; int  xss;
# };

	SYSCALLNR = %w[restart_syscall exit fork read write  open close waitpid  creat link unlink execve chdir time
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
	SYSCALLNR.update SYSCALLNR.invert
	
	SYSCALLNR_64 = %w[read write open  close stat fstat lstat poll  lseek mmap mprotect munmap  brk rt_sigaction
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
	SYSCALLNR_64.update SYSCALLNR_64.invert

	SIGNAL = Signal.list
	SIGNAL['TRAP'] ||= 5	# windows
	SIGNAL.update SIGNAL.invert

	# include/asm-generic/errno-base.h
	ERRNO = %w[ERR0 EPERM ENOENT ESRCH EINTR EIO ENXIO E2BIG ENOEXEC EBADF ECHILD EAGAIN ENOMEM EACCES EFAULT
		ENOTBLK EBUSY EEXIST EXDEV ENODEV ENOTDIR EISDIR EINVAL ENFILE EMFILE ENOTTY ETXTBSY EFBIG ENOSPC
		ESPIPE EROFS EMLINK EPIPE EDOM ERANGE].inject({}) { |h, e| h.update e => h.length }
	ERRNO.update ERRNO.invert

	def sys_ptrace(req, pid, addr, data)
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

	def cont(sig = 0)
		sys_ptrace(COMMAND['CONT'], @pid, 0, sig)
	end

	def kill
		sys_ptrace(COMMAND['KILL'], @pid, 0, 0)
	end

	def singlestep(sig = 0)
		sys_ptrace(COMMAND['SINGLESTEP'], @pid, 0, sig)
	end

	def syscall(sig = 0)
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
end

class LinOS < OS
	class Process < OS::Process
		# returns/create a LinuxRemoteString
		def memory
			@memory ||= LinuxRemoteString.new(pid)
		end
		def memory=(m) @memory = m end

		def debugger
			@debugger ||= LinDebugger.new(@pid)
		end
		def debugger=(d) @debugger = d end

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
		end

		# returns a list of threads sharing this process address space
		# read from /proc/pid/task/
		def threads
			Dir.entries("/proc/#{pid}/task/").grep(/\d+/).map { |tid| tid.to_i }
	       	rescue
			# TODO handle pthread stuff (eg 2.4 kernels)
			[pid]
		end

		# return the invocation commandline, from /proc/pid/cmdline
		# this is manipulable by the target itself
		def cmdline
			File.read("/proc/#{pid}/cmdline")
		rescue
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
	end

	# returns an array of Processes, with pid/module listing
	def self.list_processes
		Dir.entries('/proc').grep(/^\d+$/).map { |pid|
			open_process(pid.to_i)
		}
	end

	# search a Process whose pid/cmdline matches the argument
	def self.find_process(tg)
		if tg.kind_of? String and t = list_processes.find { |pr| pr.pid != ::Process.pid and pr.cmdline =~ /#{tg}/ }
			return t
		end
		super(tg)
	end

	# return a Process for the specified pid if it exists in /proc
	def self.open_process(pid)
		Process.new(pid) if File.directory?("/proc/#{pid}")
	end

	# create a LinDebugger on the target pid/binary
	def self.create_debugger(path)
		LinDebugger.new(path)
	end
end

module ::Process
	WALL   = 0x40000000 if not defined? WALL
	WCLONE = 0x80000000 if not defined? WCLONE
end

# this class implements a high-level API over the ptrace debugging primitives
class LinDebugger < Debugger
	attr_accessor :ptrace, :pass_exceptions, :continuesignal

	attr_accessor :stop_on_threadcreate, :stop_on_threadexit
	attr_accessor :callback_threadcreate, :callback_threadexit, :callback_ignoresig

	def initialize(pid, mem=nil)
		@ptrace = PTrace.new(pid)
		reinit(mem)
		@pass_exceptions = true
		@trace_children = true
		super()
		get_thread_list(@pid).each { |tid| attach_thread(tid) }
	end

	def os_process
		LinOS.open_process(@pid)
	end

	# recreate all internal state associated to pid
	def reinit(mem=nil)
		ptrace.tweak_for_pid
		@tid = @pid = ptrace.pid
		@threads = { @tid => { :state => :stopped } }	# TODO regs_cache, hwbp, singlestepcb, continuesig, breaking...
		@cpu = LinOS.open_process(@pid).cpu
		if @cpu.size == 64 and @ptrace.reg_off['EAX']
			hack_64_32
		end
		@memory = mem || LinuxRemoteString.new(@pid)
		@memory.dbg = self
		@has_pax = false
		@continuesignal = 0
		@reg_val_cache = {}
		@breaking = false
	end

	# we're a 32bit process debugging a 64bit target
	# the ptrace kernel interface we use only allow us a 32bit-like target access
	# with this we advertize the cpu as having eax..edi registers (the only one we
	# can access), while still decoding x64 instructions (whose addr < 4G)
	def hack_64_32
		puts "WARNING: debugging a 64bit process from a 32bit debugger is a very bad idea !"
		@cpu.instance_eval {
			ia32 = Ia32.new
			@dbg_register_pc = ia32.dbg_register_pc
			@dbg_register_flags = ia32.dbg_register_flags
			@dbg_register_list = ia32.dbg_register_list
			@dbg_register_size = ia32.dbg_register_size
		}
	end

	def attach_thread(tid)
		@ptrace.pid = tid
		if not @threads[tid] or @threads[tid][:state] == :new
			@ptrace.attach
			@threads[tid] ||= { :regs_cache => {} }
			@threads[tid][:state] = :stopped
			puts "attached thread #{tid}"
		end
		opts = ['TRACESYSGOOD', 'TRACECLONE', 'TRACEEXEC', 'TRACEEXIT']
		opts += ['TRACEFORK', 'TRACEVFORK', 'TRACEVFORKDONE'] if @trace_children
		@ptrace.setoptions(*opts)
	end

	def trace_children; @trace_children end
	def trace_children=(t)
		@trace_children=t
		if @state == :running
			self.break
			do_wait_target
		end
		get_thread_list(@pid).each { |tid| attach_thread(tid) }
	end

	def tid=(t)
		@tid_changed = (@tid != t)
		if @tid_changed
			@reg_val_cache.clear
			@state = @threads[tid][:state] rescue @state
		end
		@tid = @ptrace.pid = t
	end

	def get_thread_list(pid=@pid)
		LinOS.open_process(pid).threads
	end

	def get_process_list
		[@pid]
	end

	def invalidate
		@reg_val_cache.clear
		super()
	end

	def get_reg_value(r)
		raise "bad register #{r}" if not k = @ptrace.reg_off[r.to_s.upcase]
		return @reg_val_cache[r] || 0 if @state != :stopped
		@reg_val_cache[r] ||= @ptrace.peekusr(k)
	end
	def set_reg_value(r, v)
		raise "bad register #{r}" if not k = @ptrace.reg_off[r.to_s.upcase]
		@reg_val_cache[r] = v
		return if @state != :stopped
		@ptrace.pokeusr(k, v)
	end

	def update_waitpid
		if $?.exited?
			@info = "#@tid exitcode #{$?.exitstatus}"
			puts @info
			@threads.delete @tid
			self.tid = @threads.keys.first || @tid
			@state = @threads.empty? ? :dead : @threads[@tid][:state]
		elsif $?.signaled?
			@info = "#@tid signalx #{$?.termsig} #{PTrace::SIGNAL[$?.termsig]}"
			puts @info
			@threads.delete @tid
			self.tid = @threads.keys.first || @tid
			@state = @threads.empty? ? :dead : @threads[@tid][:state]
		elsif $?.stopped?
			sig = $?.stopsig & 0x7f
			if sig == PTrace::SIGNAL['TRAP']	# possible ptrace event 
				return if not @threads[@tid]
				@state = @threads[@tid][:state] = :stopped
				if $?.stopsig & 0x80 > 0
					@info = "#@tid syscall #{@ptrace.syscallnr[get_reg_value(:orig_eax)]}"
					puts @info
					if @target_syscall and @info !~ /#@target_syscall/
					       	syscall(@target_syscall)
						return if @state == :running
					end
				elsif ($? >> 16) > 0
					o = PTrace::WAIT_EXTENDEDRESULT[$? >> 16]
					case o
					when 'EVENT_FORK', 'EVENT_VFORK'
						@memory.readfd = nil	# can't read from /proc/parentpid/mem anymore
						cld = @ptrace.geteventmsg
						@threads[cld] ||= {}
						@threads[cld][:state] ||= :new	# may have already handled STOP
					when 'EVENT_CLONE'
						cld = @ptrace.geteventmsg
						@threads[cld] ||= {}
						@threads[cld][:state] ||= :new	# may have already handled STOP
						return run_resume unless stop_on_threadcreate
					when 'EVENT_EXIT'
						@threads[@tid][:state] = :dead
						@callback_threadexit[@tid] if callback_threadexit
						return run_resume unless stop_on_threadexit
					when 'EVENT_EXEC'
						# XXX clear maps/syms/bpx..
						# also check if it kills the other threads
						reinit
					when 'EVENT_VFORKDONE'
					end
					@info = "#@tid trace event #{o}"
					puts @info
				else
					@info = nil	# standard breakpoint, no need for specific info
							# TODO check target-initiated #i3 (antidebug etc)
					puts "#@tid breakpoint break" if @tid_changed
				end
				@continuesignal = 0
			elsif sig == PTrace::SIGNAL['STOP'] and ((@threads[@tid] ||= {})[:state] ||= :new) == :new
				@memory.readfd = nil if not get_thread_list(@pid).include? @tid	# FORK, can't read from /proc/parentpid/mem anymore
				@state = @threads[@tid][:state] = :stopped
				@info = "#@tid new thread started"
				puts @info
				@callback_threadcreate[@tid] if callback_threadcreate
				return do_continue unless stop_on_threadcreate
				@continuesignal = 0
			else
				return if not @threads[@tid]	# spurious sig ?
				@state = @threads[@tid][:state] = :stopped
				if @breaking and sig == PTrace::SIGNAL['STOP']
					@info = nil
					puts "#@tid break"
					@continuesignal = 0
					@breaking = nil
				elsif want_ignore_signal($?.stopsig)
					sig = @continuesignal = $?.stopsig
					puts "#@tid ignored signal #{sig} #{PTrace::SIGNAL[sig]}"
					return run_resume
				else
					sig = @continuesignal = $?.stopsig
					@info = "#@tid signal #{sig} #{PTrace::SIGNAL[sig]}"
				end
			end
		else
			@state = :stopped
			@info = "#@tid unknown wait #{$?.inspect} #{'%x' % ($? >> 16)}"
			puts @info
		end
		@target_syscall = nil
	end
	
	# check if we are supposed to ignore the signal sig
	def want_ignore_signal(sig)
		callback_ignoresig ? @callback_ignoresig[sig] : sig == PTrace::SIGNAL['WINCH']
	end

	def do_check_target
		return unless t = ::Process.waitpid(-1, ::Process::WNOHANG | ::Process::WALL)
		loop do
			self.tid = t
			invalidate
			update_waitpid
			break if not t = ::Process.waitpid(-1, ::Process::WNOHANG | ::Process::WALL)
		end
	rescue ::Errno::ECHILD
		@state = :dead
	end

	def do_wait_target
		t = ::Process.waitpid(-1, ::Process::WALL)
		self.tid = t
		invalidate
		update_waitpid
		do_check_target if @state != :dead
	rescue ::Errno::ECHILD
		@state = :dead
	end

	# resume execution of the target, ignoring the current stop cause
	# must be called before updating @info
	def run_resume
		case @info
		when 'singlestep'; do_singlestep
		when 'syscall'; syscall
		when 'continue'; do_continue
		else do_singlestep	# ?
		end
		@state = :running
	end

	def parse_run_signal(sig)
		case sig
		when nil; (@pass_exceptions ? parse_run_signal(@continuesignal || 0) : 0)
		when ::Integer; sig 
		when ::String, ::Symbol
			PTrace::SIGNAL[sig.to_s.upcase.sub(/SIG_?/, '')] || Integer(sig)
		else
			raise "invalid continue signal #{sig.inspect}"
		end
	rescue ::ArgumentError
		raise "invalid continue signal #{sig.inspect}"
	end

	def do_continue(*a)
		return if @state != :stopped
		@threads.each { |tid, tdata|
			# TODO continue only a userconfigured subset of threads
			next if tdata[:state] == :running
			tdata[:state] = :running
			sig = parse_run_signal(a.first)
			@ptrace.pid = tid
			@ptrace.cont(sig)
		}
		@ptrace.pid = @tid
		@state = :running
		@info = 'continue'
	end

	def do_singlestep(*a)
		return if @state != :stopped
		@threads[tid][:state] = :running
		@state = :running
		@info = 'singlestep'
		sig = parse_run_signal(a.first)
		@ptrace.singlestep(sig)
	end

	def need_stepover(di)
		di and ((di.instruction.prefix and di.instruction.prefix[:rep]) or di.opcode.props[:saveip])
	end

	def break
		@breaking = true
		kill('STOP')
	end

	def kill(sig=nil)
		sig = 9 if not sig or sig == ''
		sig = PTrace::SIGNAL[sig] || sig.to_i
		@threads.each_key { |tid| ::Process.kill(sig, tid) }
		@state = :running
	end

	def detach
		# TODO detach only current thread ?
		super()
		@threads.each_key { |tid|
			@ptrace.pid = tid
			@ptrace.detach
		}
		@threads.clear
		@state = :dead
		@info = 'detached'
	end

	def bpx(addr, *a)
		return hwbp(addr, :x, 1, *a) if @has_pax
		super(addr, *a)
	end

	def syscall(arg=nil)
		return if @state != :stopped
		check_pre_run
		@state = :running
		@info = 'syscall'
		@target_syscall = arg
		sig = parse_run_signal(nil)
		@threads.each { |tid, tdata|
			next if tdata[:state] != :stopped
			tdata[:state] = :running
			@ptrace.pid = tid
			@ptrace.syscall(sig)
		}
		@ptrace.pid = @tid
	end

	def enable_bp(addr)
		return if not b = @breakpoint[addr]
		case b.type
		when :bpx
			begin
				@cpu.dbg_enable_bp(self, addr, b)
			rescue ::Errno::EIO
				@memory[addr, 1]	# check if we can read
				# if yes, it's a PaX-style config
				@has_pax = true
				b.type = :hw
				b.mtype = :x
				b.mlen = 1
				@cpu.dbg_enable_bp(self, addr, b)
			end
		when :hw
			@cpu.dbg_enable_bp(self, addr, b)
		end
		b.state = :active
	end

	def disable_bp(addr)
		return if not b = @breakpoint[addr]
		@cpu.dbg_disable_bp(self, addr, b)
		b.state = :inactive
	end

	def ui_command_setup(ui)
		ui.new_command('syscall', 'waits for the target to do a syscall using PT_SYSCALL') { |arg| ui.wrap_run { syscall arg } }
		ui.keyboard_callback[:f6] = lambda { ui.wrap_run { syscall } }

		ui.new_command('threads_raw', 'list threads from the OS') { puts get_thread_list(@pid).join(', ') }
		ui.new_command('threads', 'list threads') { @threads.each { |t, s| puts "#{t} #{s[:state]}" } }
		ui.new_command('tid', 'set/get current thread id') { |arg|
			if arg.strip == ''; puts self.tid
			else self.tid = arg.to_i
			end
		}
		ui.new_command('stop_on_threadcreate') { |arg| @stop_on_threadcreate = ((arg =~ /1|true|y/i) ? true : false) }
		ui.new_command('stop_on_threadexit')   { |arg| @stop_on_threadexit   = ((arg =~ /1|true|y/i) ? true : false) }
		ui.new_command('signal_cont', 'set/get the continue signal (0 == unset)') { |arg|
			case arg.strip
			when ''; puts @continuesignal
			when /^\d+$/; @continuesignal = arg.to_i
			else @continuesignal = arg.strip.upcase.sub(/^SIG_?/, '')
			end
		}
		ui.new_command('trace_children', 'set/get the children tracing state') { |arg|
			case arg.strip.downcase
			when ''; puts self.trace_children
			when '0', 'false', 'no'; self.trace_children = false
			when '1', 'true', 'yes'; self.trace_children = true
			else raise 'trace_children: bad value, set to "true" or "false"'
			end
		}
	end
end

class LinuxRemoteString < VirtualString
	attr_accessor :pid, :readfd, :invalid_addr
	attr_accessor :dbg

	# returns a virtual string proxying the specified process memory range
	# reads are cached (4096 aligned bytes read at once), from /proc/pid/mem
	# writes are done directly by ptrace
	def initialize(pid, addr_start=0, length=nil, dbg=nil)
		@pid = pid
		length ||= 1 << (LinOS.open_process(@pid).addrsz rescue 32)
		@readfd = File.open("/proc/#@pid/mem", 'rb') rescue nil
		@dbg = dbg if dbg
		@invalid_addr = false
		super(addr_start, length)
	end

	def dup(addr = @addr_start, len = @length)
		self.class.new(@pid, addr, len, dbg)
	end

	def do_ptrace
		if dbg
			if @dbg.state == :stopped
				yield @dbg.ptrace
			end
		else
			PTrace.open(@pid) { |ptrace| yield ptrace }
		end
	end

	def rewrite_at(addr, data)
		# target must be stopped
		do_ptrace { |ptrace| ptrace.writemem(addr, data) }
	end

	def get_page(addr, len=@pagelength)
		do_ptrace {
			begin
				if readfd
					#addr = [addr].pack('q').unpack('q').first if addr >= 1<<63
					return if addr >= 1 << 63	# XXX ruby bug ?
					@readfd.pos = addr
					@readfd.read len
				else
					@dbg.ptrace.readmem(addr, len)
				end
			rescue Errno::EIO, Errno::ESRCH
				nil
			end
		}
	end
end
end
