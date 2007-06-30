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
		@buf = [0].pack('L')
		@bufptr = [@buf].pack('P').unpack('L').first
		begin
			@pid = Integer(target)
			attach
			Process.wait(@pid)
		rescue ArgumentError
			if not @pid = fork
				traceme
				exec target
			end
		end
		puts "Ptrace: attached to #@pid" if $DEBUG
	end


	# interpret the value turned as an unsigned long
	def bufval
		@buf.unpack('L').first
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
		offend = off + len - 3
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
		'SS'  => 16, 'FRAME_SIZE' => 17 }

#  this struct defines the way the registers are stored on the stack during a system call.
# struct pt_regs {
#        long ebx; long ecx; long edx; long esi;
#        long edi; long ebp; long eax; int  xds;
#        int  xes; long orig_eax; long eip; int  xcs;
#        long eflags; long esp; int  xss;
# };

	def ptrace(req, pid, addr, data)
		Kernel.syscall(26, req, pid, addr, data)
	end

	def traceme
		ptrace(COMMAND['TRACEME'],  0, 0, 0)
	end

	def peektext(addr)
		ptrace(COMMAND['PEEKTEXT'], @pid, addr, 0)
	end

	def peekdata(addr)
		ptrace(COMMAND['PEEKDATA'], @pid, addr, @bufptr)
	end

	def peekusr(addr)
		ptrace(COMMAND['PEEKUSR'],  @pid, 4*addr, @bufptr)
		bufval
	end

	def poketext(addr, data)
		ptrace(COMMAND['POKETEXT'], @pid, addr, data.unpack('L').first)
	end

	def pokedata(addr, data)
		ptrace(COMMAND['POKEDATA'], @pid, addr, data.unpack('L').first)
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
	attr_accessor :pid, :readfd

	# returns a virtual string proxying the specified process memory range
	# reads are cached (4096 aligned bytes read at once), from /proc/pid/mem
	# writes are done directly by ptrace
	# XXX could fallback to ptrace if no /proc/pid...
	def initialize(pid, addr_start=0, length=0xffff_ffff)
		@pid = pid
		@readfd = File.open("/proc/#@pid/mem")
		super(addr_start, length)
	end

	def dup(addr = @addr_start, len = @length)
		self.class.new(@pid, addr, len)
	end

	def write_range(from, val)
		@invalid = true
		# attach to target, it must be stopped before reading/writing its memory (even with /proc/pid/mem)
		PTrace32.open(@pid) { |ptrace| ptrace.writemem(@addr_start + from, val) }
	end

	def get_page(addr)
		@invalid = false
		@readfd.pos = @curstart = addr & 0xffff_f000
		PTrace32.open(@pid) { @curpage = @readfd.read 4096 }
	end

	def realstring
		super
		@readfd.pos = @addr_start
		PTrace32.open(@pid) { @readfd.read @length }
	end
end
end
