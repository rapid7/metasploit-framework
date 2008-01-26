#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/os/main'

module Metasm
class PTrace32
	attr_reader :buf, :pid

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
		@buf = [0].pack('l')
		@bufptr = [@buf].pack('P').unpack('l').first
		begin
			@pid = Integer(target)
			attach
		rescue ArgumentError
			if not @pid = fork
				traceme
				exec target
			end
		end
		Process.wait(@pid)
		puts "Ptrace: attached to #@pid" if $DEBUG
	end


	# interpret the value turned as an unsigned long
	def bufval
		@buf.unpack('l').first
	end

	# reads a memory range
	def readmem(off, len)
		decal = off & 3
		buf = ''
		if decal > 0
			off -= decal
			peekdata(off)
			off += 4
			buf << @buf[decal..3]
		end
		offend = off + len
		while off < offend
			peekdata(off)
			buf << @buf[0, 4]
			off += 4
		end
		buf[0, len]
	end

	def writemem(off, str)
		decal = off & 3
		if decal > 0
			off -= decal
			peekdata(off)
			str = @buf[0...decal] + str
		end
		decal = str.length & 3
		if decal > 0
			peekdata(off+str.length-decal)
			str += @buf[decal..3]
		end
		i = 0
		while i < str.length
			pokedata(off+i, str[i, 4])
			i += 4
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
		# Arbitrarily choose the same ptrace numbers as used by the Sparc code.
		'GETREGS'         =>  12, 'SETREGS'         =>  13,
		'GETFPREGS'       =>  14, 'SETFPREGS'       =>  15,
		'GETFPXREGS'      =>  18, 'SETFPXREGS'      =>  19,
		'OLDSETOPTIONS'   =>  21, 'GET_THREAD_AREA' =>  25,
		'SET_THREAD_AREA' =>  26, 'SYSEMU'           => 31,
		'SYSEMU_SINGLESTEP'=> 32,
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
	

	REGS_I386 = {
		'EBX' => 0, 'ECX' => 1, 'EDX' => 2, 'ESI' => 3,
		'EDI' => 4, 'EBP' => 5, 'EAX' => 6, 'DS'  => 7,
		'ES'  => 8, 'FS'  => 9, 'GS'  => 10, 'ORIG_EAX' => 11,
		'EIP' => 12, 'CS'  => 13, 'EFL' => 14, 'UESP'=> 15,
		'EFLAGS' => 14, 'ESP' => 15,
		'SS'  => 16, 'FRAME_SIZE' => 17,
		# from ptrace.c in kernel source & asm-i386/user.h
		'DR0' => 63, 'DR1' => 64, 'DR2' => 65, 'DR3' => 66,
		'DR4' => 67, 'DR5' => 68, 'DR6' => 69, 'DR7' => 70
	}

#  this struct defines the way the registers are stored on the stack during a system call.
# struct pt_regs {
#        long ebx; long ecx; long edx; long esi;
#        long edi; long ebp; long eax; int  xds;
#        int  xes; long orig_eax; long eip; int  xcs;
#        long eflags; long esp; int  xss;
# };

	SYSCALLNR = {
	'restart_syscall' => 0, 'exit' => 1, 'fork' => 2, 'read' => 3,
	'write' => 4, 'open' => 5, 'close' => 6, 'waitpid' => 7,
	'creat' => 8, 'link' => 9, 'unlink' => 10, 'execve' => 11,
	'chdir' => 12, 'time' => 13, 'mknod' => 14, 'chmod' => 15,
	'lchown' => 16, 'break' => 17, 'oldstat' => 18, 'lseek' => 19,
	'getpid' => 20, 'mount' => 21, 'umount' => 22, 'setuid' => 23,
	'getuid' => 24, 'stime' => 25, 'ptrace' => 26, 'alarm' => 27,
	'oldfstat' => 28, 'pause' => 29, 'utime' => 30, 'stty' => 31,
	'gtty' => 32, 'access' => 33, 'nice' => 34, 'ftime' => 35,
	'sync' => 36, 'kill' => 37, 'rename' => 38, 'mkdir' => 39,
	'rmdir' => 40, 'dup' => 41, 'pipe' => 42, 'times' => 43,
	'prof' => 44, 'brk' => 45, 'setgid' => 46, 'getgid' => 47,
	'signal' => 48, 'geteuid' => 49, 'getegid' => 50, 'acct' => 51,
	'umount2' => 52, 'lock' => 53, 'ioctl' => 54, 'fcntl' => 55,
	'mpx' => 56, 'setpgid' => 57, 'ulimit' => 58, 'oldolduname' => 59,
	'umask' => 60, 'chroot' => 61, 'ustat' => 62, 'dup2' => 63,
	'getppid' => 64, 'getpgrp' => 65, 'setsid' => 66, 'sigaction' => 67,
	'sgetmask' => 68, 'ssetmask' => 69, 'setreuid' => 70, 'setregid' => 71,
	'sigsuspend' => 72, 'sigpending' => 73, 'sethostname' => 74, 'setrlimit' => 75,
	'getrlimit' => 76, 'getrusage' => 77, 'gettimeofday' => 78, 'settimeofday' => 79,
	'getgroups' => 80, 'setgroups' => 81, 'select' => 82, 'symlink' => 83,
	'oldlstat' => 84, 'readlink' => 85, 'uselib' => 86, 'swapon' => 87,
	'reboot' => 88, 'readdir' => 89, 'mmap' => 90, 'munmap' => 91,
	'truncate' => 92, 'ftruncate' => 93, 'fchmod' => 94, 'fchown' => 95,
	'getpriority' => 96, 'setpriority' => 97, 'profil' => 98, 'statfs' => 99,
	'fstatfs' => 100, 'ioperm' => 101, 'socketcall' => 102, 'syslog' => 103,
	'setitimer' => 104, 'getitimer' => 105, 'stat' => 106, 'lstat' => 107,
	'fstat' => 108, 'olduname' => 109, 'iopl' => 110, 'vhangup' => 111,
	'idle' => 112, 'vm86old' => 113, 'wait4' => 114, 'swapoff' => 115,
	'sysinfo' => 116, 'ipc' => 117, 'fsync' => 118, 'sigreturn' => 119,
	'clone' => 120, 'setdomainname' => 121, 'uname' => 122, 'modify_ldt' => 123,
	'adjtimex' => 124, 'mprotect' => 125, 'sigprocmask' => 126, 'create_module' => 127,
	'init_module' => 128, 'delete_module' => 129, 'get_kernel_syms' => 130, 'quotactl' => 131,
	'getpgid' => 132, 'fchdir' => 133, 'bdflush' => 134, 'sysfs' => 135,
	'personality' => 136, 'afs_syscall' => 137, 'setfsuid' => 138, 'setfsgid' => 139,
	'_llseek' => 140, 'getdents' => 141, '_newselect' => 142, 'flock' => 143,
	'msync' => 144, 'readv' => 145, 'writev' => 146, 'getsid' => 147,
	'fdatasync' => 148, '_sysctl' => 149, 'mlock' => 150, 'munlock' => 151,
	'mlockall' => 152, 'munlockall' => 153, 'sched_setparam' => 154, 'sched_getparam' => 155,
	'sched_setscheduler' => 156, 'sched_getscheduler' => 157, 'sched_yield' => 158, 'sched_get_priority_max' => 159,
	'sched_get_priority_min' => 160, 'sched_rr_get_interval' => 161, 'nanosleep' => 162, 'mremap' => 163,
	'setresuid' => 164, 'getresuid' => 165, 'vm86' => 166, 'query_module' => 167,
	'poll' => 168, 'nfsservctl' => 169, 'setresgid' => 170, 'getresgid' => 171,
	'prctl' => 172, 'rt_sigreturn' => 173, 'rt_sigaction' => 174, 'rt_sigprocmask' => 175,
	'rt_sigpending' => 176, 'rt_sigtimedwait' => 177, 'rt_sigqueueinfo' => 178, 'rt_sigsuspend' => 179,
	'pread64' => 180, 'pwrite64' => 181, 'chown' => 182, 'getcwd' => 183,
	'capget' => 184, 'capset' => 185, 'sigaltstack' => 186, 'sendfile' => 187,
	'getpmsg' => 188, 'putpmsg' => 189, 'vfork' => 190, 'ugetrlimit' => 191,
	'mmap2' => 192, 'truncate64' => 193, 'ftruncate64' => 194, 'stat64' => 195,
	'lstat64' => 196, 'fstat64' => 197, 'lchown32' => 198, 'getuid32' => 199,
	'getgid32' => 200, 'geteuid32' => 201, 'getegid32' => 202, 'setreuid32' => 203,
	'setregid32' => 204, 'getgroups32' => 205, 'setgroups32' => 206, 'fchown32' => 207,
	'setresuid32' => 208, 'getresuid32' => 209, 'setresgid32' => 210, 'getresgid32' => 211,
	'chown32' => 212, 'setuid32' => 213, 'setgid32' => 214, 'setfsuid32' => 215,
	'setfsgid32' => 216, 'pivot_root' => 217, 'mincore' => 218, 'madvise' => 219,
	'getdents64' => 220, 'fcntl64' => 221, 'gettid' => 224, 'readahead' => 225,
	'setxattr' => 226, 'lsetxattr' => 227, 'fsetxattr' => 228, 'getxattr' => 229,
	'lgetxattr' => 230, 'fgetxattr' => 231, 'listxattr' => 232, 'llistxattr' => 233,
	'flistxattr' => 234, 'removexattr' => 235, 'lremovexattr' => 236, 'fremovexattr' => 237,
	'tkill' => 238, 'sendfile64' => 239, 'futex' => 240, 'sched_setaffinity' => 241,
	'sched_getaffinity' => 242, 'set_thread_area' => 243, 'get_thread_area' => 244, 'io_setup' => 245,
	'io_destroy' => 246, 'io_getevents' => 247, 'io_submit' => 248, 'io_cancel' => 249,
	'fadvise64' => 250, 'exit_group' => 252, 'lookup_dcookie' => 253,
	'epoll_create' => 254, 'epoll_ctl' => 255, 'epoll_wait' => 256, 'remap_file_pages' => 257,
	'set_tid_address' => 258, 'timer_create' => 259, 'timer_settime' => 260, 'timer_gettime' => 261,
	'timer_getoverrun' => 262, 'timer_delete' => 263, 'clock_settime' => 264, 'clock_gettime' => 265,
	'clock_getres' => 266, 'clock_nanosleep' => 267, 'statfs64' => 268, 'fstatfs64' => 269,
	'tgkill' => 270, 'utimes' => 271, 'fadvise64_64' => 272, 'vserver' => 273,
	'mbind' => 274, 'get_mempolicy' => 275, 'set_mempolicy' => 276, 'mq_open' => 277,
	'mq_unlink' => 278, 'mq_timedsend' => 279, 'mq_timedreceive' => 280, 'mq_notify' => 281,
	'mq_getsetattr' => 282, 'kexec_load' => 283, 'waitid' => 284, 'sys_setaltroot' => 285,
	'add_key' => 286, 'request_key' => 287, 'keyctl' => 288, 'ioprio_set' => 289,
	'ioprio_get' => 290, 'inotify_init' => 291, 'inotify_add_watch' => 292, 'inotify_rm_watch' => 293,
	'migrate_pages' => 294, 'openat' => 295, 'mkdirat' => 296, 'mknodat' => 297,
	'fchownat' => 298, 'futimesat' => 299, 'fstatat64' => 300, 'unlinkat' => 301,
	'renameat' => 302, 'linkat' => 303, 'symlinkat' => 304, 'readlinkat' => 305,
	'fchmodat' => 306, 'faccessat' => 307, 'pselect6' => 308, 'ppoll' => 309,
	'unshare' => 310, 'set_robust_list' => 311, 'get_robust_list' => 312, 'splice' => 313,
	'sync_file_range' => 314, 'tee' => 315, 'vmsplice' => 316, 'move_pages' => 317,
	'getcpu' => 318, 'epoll_pwait' => 319, 'utimensat' => 320, 'signalfd' => 321,
	'timerfd' => 322, 'eventfd' => 323 }

	def ptrace(req, pid, addr, data)
		addr = [addr].pack('L').unpack('l').first if addr >= 0x8000_0000
		Kernel.syscall(26, req, pid, addr, data)
	end

	def traceme
		ptrace(COMMAND['TRACEME'],  0, 0, 0)
	end

	def peektext(addr)
		ptrace(COMMAND['PEEKTEXT'], @pid, addr, @bufptr)
		@buf
	end

	def peekdata(addr)
		ptrace(COMMAND['PEEKDATA'], @pid, addr, @bufptr)
		@buf
	end

	def peekusr(addr)
		ptrace(COMMAND['PEEKUSR'],  @pid, 4*addr, @bufptr)
		bufval
	end

	def poketext(addr, data)
		ptrace(COMMAND['POKETEXT'], @pid, addr, data.unpack('l').first)
	end

	def pokedata(addr, data)
		ptrace(COMMAND['POKEDATA'], @pid, addr, data.unpack('l').first)
	end

	def pokeusr(addr, data)
		ptrace(COMMAND['POKEUSR'],  @pid, 4*addr, data)
	end

	def cont(sig = 0)
		ptrace(COMMAND['CONT'], @pid, 0, sig)
	end

	def kill
		ptrace(COMMAND['KILL'], @pid, 0, 0)
	end

	def singlestep(sig = 0)
		ptrace(COMMAND['SINGLESTEP'], @pid, 0, sig)
	end

	def syscall
		ptrace(COMMAND['SYSCALL'], @pid, 0, 0)
	end

	def attach
		ptrace(COMMAND['ATTACH'], @pid, 0, 0)
	end

	def detach
		ptrace(COMMAND['DETACH'], @pid, 0, 0)
	end
end

class LinuxRemoteString < VirtualString
	attr_accessor :pid, :readfd, :invalid_addr
	attr_accessor :ptrace

	# returns a virtual string proxying the specified process memory range
	# reads are cached (4096 aligned bytes read at once), from /proc/pid/mem
	# writes are done directly by ptrace
	# XXX could fallback to ptrace if no /proc/pid...
	def initialize(pid, addr_start=0, length=0xffff_ffff, ptrace=nil)
		@pid = pid
		@readfd = File.open("/proc/#@pid/mem")
		@ptrace = ptrace if ptrace
		@invalid_addr = false
		super(addr_start, length)
	end

	def dup(addr = @addr_start, len = @length)
		self.class.new(@pid, addr, len, ptrace)
	end

	def do_ptrace
		if ptrace
			yield @ptrace
		else
			PTrace32.open(@pid) { |ptrace| yield ptrace }
		end
	end

	def rewrite_at(addr, data)
		# target must be stopped
		do_ptrace { |ptrace| ptrace.writemem(addr, data) }
	end

	def get_page(addr)
		@readfd.pos = addr
		# target must be stopped
		do_ptrace {
			begin
				@readfd.read 4096
			rescue Errno::EIO
				nil
			end
		}
	end

	def realstring
		super
		@readfd.pos = @addr_start
		do_ptrace { @readfd.read @length }
	end
end

class GNUExports
	# exported symbol name => exporting library name for common libraries
	# used by ELF#automagic_symbols
	EXPORT = {}
	# see samples/elf_listexports for the generator of this data
	data = <<EOL	# XXX libraries do not support __END__/DATA...
libc.so.6
 _IO_adjust_column _IO_adjust_wcolumn _IO_default_doallocate _IO_default_finish _IO_default_pbackfail _IO_default_uflow _IO_default_xsgetn _IO_default_xsputn
 _IO_do_write _IO_do_write _IO_doallocbuf _IO_fclose _IO_fclose _IO_fdopen _IO_fdopen _IO_feof _IO_ferror _IO_fflush _IO_fgetpos _IO_fgetpos _IO_fgetpos64
 _IO_fgetpos64 _IO_fgets _IO_file_attach _IO_file_attach _IO_file_close _IO_file_close_it _IO_file_close_it _IO_file_doallocate _IO_file_finish _IO_file_fopen
 _IO_file_fopen _IO_file_init _IO_file_init _IO_file_open _IO_file_overflow _IO_file_overflow _IO_file_read _IO_file_seek _IO_file_seekoff _IO_file_seekoff
 _IO_file_setbuf _IO_file_setbuf _IO_file_stat _IO_file_sync _IO_file_sync _IO_file_underflow _IO_file_underflow _IO_file_write _IO_file_write _IO_file_xsputn
 _IO_file_xsputn _IO_flockfile _IO_flush_all _IO_flush_all_linebuffered _IO_fopen _IO_fopen _IO_fputs _IO_fread _IO_free_backup_area _IO_free_wbackup_area
 _IO_fsetpos _IO_fsetpos _IO_fsetpos64 _IO_fsetpos64 _IO_ftell _IO_ftrylockfile _IO_funlockfile _IO_fwrite _IO_getc _IO_getline _IO_getline_info _IO_gets
 _IO_init _IO_init_marker _IO_init_wmarker _IO_iter_begin _IO_iter_end _IO_iter_file _IO_iter_next _IO_least_wmarker _IO_link_in _IO_list_lock
 _IO_list_resetlock _IO_list_unlock _IO_marker_delta _IO_marker_difference _IO_padn _IO_peekc_locked _IO_popen _IO_popen _IO_printf _IO_proc_close
 _IO_proc_close _IO_proc_open _IO_proc_open _IO_putc _IO_puts _IO_remove_marker _IO_seekmark _IO_seekoff _IO_seekpos _IO_seekwmark _IO_setb _IO_setbuffer
 _IO_setvbuf _IO_sgetn _IO_sprintf _IO_sputbackc _IO_sputbackwc _IO_sscanf _IO_str_init_readonly _IO_str_init_static _IO_str_overflow _IO_str_pbackfail
 _IO_str_seekoff _IO_str_underflow _IO_sungetc _IO_sungetwc _IO_switch_to_get_mode _IO_switch_to_main_wget_area _IO_switch_to_wbackup_area
 _IO_switch_to_wget_mode _IO_un_link _IO_ungetc _IO_unsave_markers _IO_unsave_wmarkers _IO_vfprintf _IO_vfscanf _IO_vsprintf _IO_wdefault_doallocate
 _IO_wdefault_finish _IO_wdefault_pbackfail _IO_wdefault_uflow _IO_wdefault_xsgetn _IO_wdefault_xsputn _IO_wdo_write _IO_wdoallocbuf _IO_wfile_overflow
 _IO_wfile_seekoff _IO_wfile_sync _IO_wfile_underflow _IO_wfile_xsputn _IO_wmarker_delta _IO_wsetb _Unwind_Find_FDE __adjtimex __argz_count __argz_next
 __argz_stringify __asprintf __assert __assert_fail __assert_perror_fail __backtrace __backtrace_symbols __backtrace_symbols_fd __bsd_getpgrp __bzero
 __chk_fail __clone __cmpdi2 __cmsg_nxthdr __confstr_chk __ctype_b_loc __ctype_tolower_loc __ctype_toupper_loc __cxa_atexit __cxa_finalize
 __cyg_profile_func_enter __cyg_profile_func_exit __dcgettext __default_morecore __deregister_frame __deregister_frame_info __deregister_frame_info_bases
 __dgettext __divdi3 __dup2 __duplocale __endmntent __errno_location __fbufsize __ffs __fgets_chk __fgets_unlocked_chk __fgetws_chk __fgetws_unlocked_chk
 __finite __finitef __finitel __fixunsdfdi __fixunsxfdi __flbf __floatdidf __fork __fpending __fprintf_chk __fpurge __frame_state_for __freadable __freading
 __freelocale __fsetlocking __fwprintf_chk __fwritable __fwriting __fxstat __fxstat64 __fxstat64 __fxstatat __fxstatat64 __gai_sigqueue __gconv_get_alias_db
 __gconv_get_cache __gconv_get_modules_db __getcwd_chk __getdomainname_chk __getgroups_chk __gethostname_chk __getlogin_r_chk __getmntent_r __getpagesize
 __getpgid __getpid __gets_chk __gettimeofday __getwd_chk __gmtime_r __h_errno_location __internal_endnetgrent __internal_getnetgrent_r __internal_setnetgrent
 __isalnum_l __isalpha_l __isblank_l __iscntrl_l __isctype __isdigit_l __isgraph_l __isinf __isinff __isinfl __islower_l __isnan __isnanf __isnanl __isprint_l
 __ispunct_l __isspace_l __isupper_l __iswalnum_l __iswalpha_l __iswblank_l __iswcntrl_l __iswctype __iswctype_l __iswdigit_l __iswgraph_l __iswlower_l
 __iswprint_l __iswpunct_l __iswspace_l __iswupper_l __iswxdigit_l __isxdigit_l __ivaliduser __libc_allocate_rtsig __libc_allocate_rtsig_private __libc_calloc
 __libc_current_sigrtmax __libc_current_sigrtmax_private __libc_current_sigrtmin __libc_current_sigrtmin_private __libc_dl_error_tsd __libc_dlclose
 __libc_dlopen_mode __libc_dlsym __libc_fatal __libc_fork __libc_free __libc_freeres __libc_init_first __libc_longjmp __libc_mallinfo __libc_malloc
 __libc_mallopt __libc_memalign __libc_msgrcv __libc_msgsnd __libc_pthread_init __libc_pvalloc __libc_pwrite __libc_realloc __libc_sa_len __libc_siglongjmp
 __libc_start_main __libc_system __libc_thread_freeres __libc_valloc __lxstat __lxstat64 __lxstat64 __mbrlen __mbrtowc __mbsnrtowcs_chk __mbsrtowcs_chk
 __mbstowcs_chk __memcpy_by2 __memcpy_by4 __memcpy_c __memcpy_chk __memcpy_g __memmove_chk __mempcpy __mempcpy_by2 __mempcpy_by4 __mempcpy_byn __mempcpy_chk
 __mempcpy_small __memset_cc __memset_ccn_by2 __memset_ccn_by4 __memset_cg __memset_chk __memset_gcn_by2 __memset_gcn_by4 __memset_gg __moddi3 __modify_ldt
 __monstartup __newlocale __nl_langinfo_l __nss_configure_lookup __nss_database_lookup __nss_disable_nscd __nss_group_lookup __nss_hostname_digits_dots
 __nss_hosts_lookup __nss_lookup_function __nss_next __nss_passwd_lookup __nss_services_lookup __open_catalog __overflow __pipe __poll __pread64_chk
 __pread_chk __printf_chk __printf_fp __profile_frequency __ptsname_r_chk __rawmemchr __read_chk __readlink_chk __readlinkat_chk __realpath_chk __recv_chk
 __recvfrom_chk __register_atfork __register_frame __register_frame_info __register_frame_info_bases __register_frame_info_table
 __register_frame_info_table_bases __register_frame_table __res_iclose __res_init __res_maybe_init __res_nclose __res_ninit __res_randomid __res_state
 __rpc_thread_createerr __rpc_thread_svc_fdset __rpc_thread_svc_max_pollfd __rpc_thread_svc_pollfd __sbrk __sched_cpucount __sched_get_priority_max
 __sched_get_priority_min __sched_getparam __sched_getscheduler __sched_setscheduler __sched_yield __secure_getenv __select __setmntent __setpgid __sigaddset
 __sigdelset __sigismember __signbit __signbitf __signbitl __sigpause __sigsetjmp __sigsuspend __snprintf_chk __sprintf_chk __stack_chk_fail __statfs __stpcpy
 __stpcpy_chk __stpcpy_g __stpcpy_small __stpncpy __stpncpy_chk __strcasecmp __strcasecmp_l __strcasestr __strcat_c __strcat_chk __strcat_g __strchr_c
 __strchr_g __strchrnul_c __strchrnul_g __strcmp_gg __strcoll_l __strcpy_chk __strcpy_g __strcpy_small __strcspn_c1 __strcspn_c2 __strcspn_c3 __strcspn_cg
 __strcspn_g __strdup __strerror_r __strfmon_l __strftime_l __strlen_g __strncasecmp_l __strncat_chk __strncat_g __strncmp_g __strncpy_by2 __strncpy_by4
 __strncpy_byn __strncpy_chk __strncpy_gg __strndup __strpbrk_c2 __strpbrk_c3 __strpbrk_cg __strpbrk_g __strrchr_c __strrchr_g __strsep_1c __strsep_2c
 __strsep_3c __strsep_g __strspn_c1 __strspn_c2 __strspn_c3 __strspn_cg __strspn_g __strstr_cg __strstr_g __strtod_internal __strtof_internal __strtok_r
 __strtok_r_1c __strtol_internal __strtold_internal __strtoll_internal __strtoq_internal __strtoul_internal __strtoull_internal __strtouq_internal __strverscmp
 __strxfrm_l __swprintf_chk __sysconf __sysctl __syslog_chk __sysv_signal __tolower_l __toupper_l __towctrans __towctrans_l __towlower_l __towupper_l
 __ttyname_r_chk __ucmpdi2 __udivdi3 __uflow __umoddi3 __underflow __uselocale __vfork __vfprintf_chk __vfscanf __vfwprintf_chk __vprintf_chk __vsnprintf_chk
 __vsprintf_chk __vswprintf_chk __vsyslog_chk __vwprintf_chk __waitpid __wcpcpy_chk __wcpncpy_chk __wcrtomb_chk __wcscasecmp_l __wcscat_chk __wcscoll_l
 __wcscpy_chk __wcsftime_l __wcsncasecmp_l __wcsncat_chk __wcsncpy_chk __wcsnrtombs_chk __wcsrtombs_chk __wcstod_internal __wcstof_internal __wcstol_internal
 __wcstold_internal __wcstoll_internal __wcstombs_chk __wcstoul_internal __wcstoull_internal __wcsxfrm_l __wctomb_chk __wctrans_l __wctype_l __wmemcpy_chk
 __wmemmove_chk __wmempcpy_chk __wmemset_chk __woverflow __wprintf_chk __wuflow __wunderflow __xmknod __xmknodat __xpg_basename __xpg_strerror_r __xstat
 __xstat64 __xstat64 _authenticate _dl_addr _dl_mcount_wrapper _dl_mcount_wrapper_check _dl_sym _dl_vsym _exit _mcleanup _mcount _nss_files_parse_grent
 _nss_files_parse_pwent _nss_files_parse_spent _obstack_allocated_p _obstack_begin _obstack_begin_1 _obstack_free _obstack_memory_used _obstack_newchunk
 _rpc_dtablesize _seterr_reply _setjmp _tolower _toupper a64l abort abs acct addseverity alarm alphasort alphasort64 alphasort64 argz_delete asctime atexit
 atof atoi atol atoll authdes_create authdes_getucred authdes_pk_create authnone_create authunix_create authunix_create_default basename bcopy bdflush bind
 bindresvport bsearch callrpc capget capset catclose catgets catopen cbc_crypt cfgetispeed cfgetospeed cfmakeraw cfsetispeed cfsetospeed cfsetspeed chflags
 chown chown chroot clearerr clearerr_unlocked clnt_broadcast clnt_create clnt_pcreateerror clnt_perrno clnt_perror clnt_spcreateerror clnt_sperrno
 clnt_sperror clntraw_create clnttcp_create clntudp_bufcreate clntudp_create clntunix_create clock closelog confstr creat64 create_module ctermid ctime ctime_r
 cuserid daemon delete_module des_setparity difftime dirfd dirname div dprintf drand48 drand48_r dysize ecb_crypt ecvt ecvt_r endaliasent endfsent endgrent
 endhostent endnetent endnetgrent endprotoent endpwent endrpcent endservent endspent endttyent endusershell endutxent envz_add envz_entry envz_get envz_merge
 envz_remove envz_strip epoll_create epoll_ctl epoll_pwait epoll_wait erand48 err errx ether_aton ether_aton_r ether_hostton ether_line ether_ntoa ether_ntoa_r
 ether_ntohost execl execle execlp execv execvp exit faccessat fattach fchflags fchmodat fchownat fclose fclose fcvt fcvt_r fdatasync fdetach fdopen fdopen
 feof_unlocked ferror_unlocked fexecve fflush_unlocked ffs ffsll fgetgrent fgetpos fgetpos fgetpos64 fgetpos64 fgetpwent fgets_unlocked fgetspent fgetws
 fgetws_unlocked fgetxattr fileno flistxattr fmemopen fmtmsg fnmatch fnmatch fopen fopen fopencookie fopencookie fprintf fputc fputc_unlocked fputs_unlocked
 fputwc fputwc_unlocked fputws fputws_unlocked fread_unlocked free freeaddrinfo freeifaddrs fremovexattr freopen freopen64 fscanf fseek fseeko fseeko64 fsetpos
 fsetpos fsetpos64 fsetpos64 fsetxattr fstatvfs ftello ftello64 ftime ftok fts_children fts_close fts_open fts_read fts_set ftw ftw64 futimens futimesat fwide
 fwrite_unlocked fwscanf gai_strerror gcvt get_current_dir_name get_kernel_syms get_myaddress getaddrinfo getaliasbyname getaliasbyname_r getaliasbyname_r
 getaliasent getaliasent_r getaliasent_r getchar getchar_unlocked getdate getdirentries getdirentries64 getdomainname getenv getfsent getfsfile getfsspec
 getgrent getgrent_r getgrent_r getgrgid getgrgid_r getgrgid_r getgrnam getgrnam_r getgrnam_r getgrouplist gethostbyaddr gethostbyaddr_r gethostbyaddr_r
 gethostbyname gethostbyname2 gethostbyname2_r gethostbyname2_r gethostbyname_r gethostbyname_r gethostent gethostent_r gethostent_r gethostid getifaddrs
 getipv4sourcefilter getloadavg getlogin getlogin_r getmntent getmsg getnameinfo getnetbyaddr getnetbyaddr_r getnetbyaddr_r getnetbyname getnetbyname_r
 getnetbyname_r getnetent getnetent_r getnetent_r getnetgrent getnetname getopt getopt_long getopt_long_only getpass getpgrp getpid getpmsg getpriority
 getprotobyname getprotobyname_r getprotobyname_r getprotobynumber getprotobynumber_r getprotobynumber_r getprotoent getprotoent_r getprotoent_r getpublickey
 getpwent getpwent_r getpwent_r getpwnam getpwnam_r getpwnam_r getpwuid getpwuid_r getpwuid_r getrlimit getrlimit getrlimit64 getrlimit64 getrpcbyname
 getrpcbyname_r getrpcbyname_r getrpcbynumber getrpcbynumber_r getrpcbynumber_r getrpcent getrpcent_r getrpcent_r getrpcport getsecretkey getservbyname
 getservbyname_r getservbyname_r getservbyport getservbyport_r getservbyport_r getservent getservent_r getservent_r getsid getsockname getsourcefilter getspent
 getspent_r getspent_r getspnam getspnam_r getspnam_r getsubopt getttyent getttynam getusershell getutmp getutmpx getutxent getutxid getutxline getw getwchar
 getwchar_unlocked getwd getxattr glob glob64 glob64 globfree globfree64 gmtime gnu_dev_major gnu_dev_makedev gnu_dev_minor grantpt gtty hcreate hcreate_r
 hdestroy_r herror host2netname hsearch hsearch_r hstrerror htonl htons iconv iconv_close iconv_open if_freenameindex if_indextoname if_nameindex
 if_nametoindex inet6_opt_append inet6_opt_find inet6_opt_finish inet6_opt_get_val inet6_opt_init inet6_opt_next inet6_opt_set_val inet6_option_alloc
 inet6_option_append inet6_option_find inet6_option_init inet6_option_next inet6_option_space inet6_rth_add inet6_rth_getaddr inet6_rth_init inet6_rth_reverse
 inet6_rth_segments inet6_rth_space inet_addr inet_lnaof inet_makeaddr inet_netof inet_network inet_nsap_addr inet_nsap_ntoa inet_ntoa inet_ntop inet_pton
 init_module initgroups innetgr inotify_add_watch inotify_init inotify_rm_watch insque ioperm iopl iruserok iruserok_af isalnum isalpha isascii isastream
 isblank iscntrl isdigit isfdtype isgraph islower isprint ispunct isspace isupper isxdigit jrand48 key_decryptsession key_decryptsession_pk key_encryptsession
 key_encryptsession_pk key_gendes key_get_conv key_secretkey_is_set key_setnet key_setsecret killpg klogctl l64a labs lchmod lcong48 ldiv lfind lgetxattr
 linkat listen listxattr llabs lldiv llistxattr localeconv localeconv localtime lockf lockf64 lrand48 lrand48_r lremovexattr lsearch lsetxattr lutimes madvise
 malloc mblen mbstowcs mbtowc mcheck mcheck_check_all mcheck_pedantic memcmp memcpy memfrob memmem memmove mempcpy memset mincore mkdirat mkdtemp mkfifo
 mkfifoat mkstemp mkstemp64 mktemp mktime mlock mlockall mprobe mrand48 mrand48_r msgctl msgctl msgget mtrace munlock munlockall muntrace netname2host
 netname2user nfsservctl nftw nftw nftw64 nftw64 nice nl_langinfo nrand48 ntp_gettime obstack_free open_memstream open_wmemstream openlog parse_printf_format
 passwd2des pclose pclose perror pivot_root pmap_getmaps pmap_getport pmap_rmtcall pmap_set pmap_unset popen popen posix_fadvise posix_fadvise64
 posix_fadvise64 posix_fallocate posix_fallocate64 posix_fallocate64 posix_madvise posix_spawn posix_spawn_file_actions_addclose
 posix_spawn_file_actions_adddup2 posix_spawn_file_actions_addopen posix_spawn_file_actions_destroy posix_spawn_file_actions_init posix_spawnattr_destroy
 posix_spawnattr_getflags posix_spawnattr_getpgroup posix_spawnattr_getschedparam posix_spawnattr_getschedpolicy posix_spawnattr_getsigdefault
 posix_spawnattr_getsigmask posix_spawnattr_init posix_spawnattr_setflags posix_spawnattr_setpgroup posix_spawnattr_setschedparam
 posix_spawnattr_setschedpolicy posix_spawnattr_setsigdefault posix_spawnattr_setsigmask posix_spawnp ppoll printf printf_size printf_size_info psignal
 pthread_attr_destroy pthread_attr_getdetachstate pthread_attr_getinheritsched pthread_attr_getschedparam pthread_attr_getschedpolicy pthread_attr_getscope
 pthread_attr_init pthread_attr_init pthread_attr_setdetachstate pthread_attr_setinheritsched pthread_attr_setschedparam pthread_attr_setschedpolicy
 pthread_attr_setscope pthread_cond_broadcast pthread_cond_broadcast pthread_cond_destroy pthread_cond_destroy pthread_cond_init pthread_cond_init
 pthread_cond_signal pthread_cond_signal pthread_cond_timedwait pthread_cond_timedwait pthread_cond_wait pthread_cond_wait pthread_condattr_destroy
 pthread_condattr_init pthread_equal pthread_exit pthread_getschedparam pthread_mutex_destroy pthread_mutex_init pthread_mutex_lock pthread_mutex_unlock
 pthread_self pthread_setcanceltype pthread_setschedparam ptrace ptsname putc_unlocked putchar putchar_unlocked putenv putgrent putmsg putpmsg putpwent
 putspent pututxline putw putwc putwc_unlocked putwchar putwchar_unlocked qecvt qecvt_r qfcvt qfcvt_r qgcvt qsort query_module quotactl raise rand rand_r rcmd
 rcmd_af readdir64 readdir64 readdir64_r readdir64_r readlinkat realloc realpath realpath reboot regexec regexec registerrpc remove removexattr remque rename
 renameat revoke rewind rewinddir rexec rexec_af rpmatch rresvport rresvport_af rtime ruserok ruserok_af ruserpass scandir scandir64 scandir64 scanf
 sched_getaffinity sched_getaffinity sched_getcpu sched_setaffinity sched_setaffinity seed48 seekdir semctl semctl semget semop semtimedop sendfile sendfile64
 setaliasent setbuf setdomainname setegid seteuid setfsent setfsgid setfsuid setgrent setgroups sethostent sethostid sethostname setipv4sourcefilter setjmp
 setlinebuf setlocale setlogin setlogmask setnetent setnetgrent setpgrp setpriority setprotoent setpwent setrlimit setrlimit setrlimit64 setrpcent setservent
 setsockopt setsourcefilter setspent setttyent setusershell setutxent setxattr sgetspent shmat shmctl shmctl shmdt shmget sigaddset sigandset sigdelset
 sigemptyset sigfillset siggetmask sighold sigignore siginterrupt sigisemptyset sigismember sigorset sigpending sigrelse sigset sigstack sockatmark splice
 sprintf srand48 sscanf sstk statvfs stime strcat strchr strcmp strcoll strcpy strcspn strerror strerror_l strfmon strfry strftime strlen strncat strncmp
 strncpy strnlen strpbrk strptime strrchr strsignal strspn strstr strtoimax strtok strtol strtoll strtoul strtoull strtoumax strxfrm stty svc_exit svc_getreq
 svc_getreq_common svc_getreq_poll svc_getreqset svc_register svc_run svc_sendreply svc_unregister svcerr_auth svcerr_decode svcerr_noproc svcerr_noprog
 svcerr_progvers svcerr_systemerr svcerr_weakauth svcfd_create svcraw_create svctcp_create svcudp_bufcreate svcudp_create svcudp_enablecache svcunix_create
 svcunixfd_create swab swprintf swscanf symlinkat sync sync_file_range syscall sysinfo syslog tcflow tcflush tcgetpgrp tcgetsid tcsendbreak tcsetattr tcsetpgrp
 tee telldir tempnam time timegm tmpfile tmpfile tmpfile64 tmpnam tmpnam_r toascii tolower toupper towlower towupper tr_break truncate64 ttyname ttyslot ualarm
 ungetwc unlinkat unlockpt unshare updwtmpx uselib user2netname usleep ustat utime utimensat utmpxname verr verrx versionsort versionsort64 versionsort64
 vfprintf vhangup vlimit vm86 vm86 vmsplice vprintf vswscanf vsyslog vtimes vwarn vwarnx vwprintf vwscanf warn warnx wcschr wcscmp wcscpy wcscspn wcsdup
 wcsftime wcsncat wcsncmp wcspbrk wcsrchr wcsspn wcsstr wcstoimax wcstok wcstol wcstoll wcstombs wcstoul wcstoull wcstoumax wcswidth wcsxfrm wctob wctomb
 wcwidth wmemchr wmemcmp wmemset wordexp wordfree wprintf wscanf xdecrypt xdr_accepted_reply xdr_array xdr_authdes_cred xdr_authdes_verf xdr_authunix_parms
 xdr_bool xdr_bytes xdr_callhdr xdr_callmsg xdr_char xdr_cryptkeyarg xdr_cryptkeyarg2 xdr_cryptkeyres xdr_des_block xdr_double xdr_enum xdr_float xdr_free
 xdr_getcredres xdr_hyper xdr_int xdr_int16_t xdr_int32_t xdr_int64_t xdr_int8_t xdr_key_netstarg xdr_key_netstres xdr_keybuf xdr_keystatus xdr_long
 xdr_longlong_t xdr_netnamestr xdr_netobj xdr_opaque xdr_opaque_auth xdr_pmap xdr_pmaplist xdr_pointer xdr_quad_t xdr_reference xdr_rejected_reply xdr_replymsg
 xdr_rmtcall_args xdr_rmtcallres xdr_short xdr_sizeof xdr_string xdr_u_char xdr_u_hyper xdr_u_int xdr_u_long xdr_u_longlong_t xdr_u_quad_t xdr_u_short
 xdr_uint16_t xdr_uint32_t xdr_uint64_t xdr_uint8_t xdr_union xdr_unixcred xdr_vector xdr_void xdr_wrapstring xdrmem_create xdrrec_create xdrrec_endofrecord
 xdrrec_eof xdrrec_skiprecord xdrstdio_create xencrypt xprt_register xprt_unregister
EOL
	curlibname = nil
	data.each { |l|
		list = l.split
		curlibname = list.shift if l[0, 1] != ' '
		list.each { |export| EXPORT[export] = curlibname }
	}
end
end
