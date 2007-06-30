#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/os/main'
begin
require 'Win32API'
rescue LoadError
end

module Metasm
module WinAPI
	class Process
		attr_accessor :pid, :modules
		class Module
			attr_accessor :path, :addr
		end
		def to_s
			"pid #{pid}:".ljust(6) + ((@modules and @modules.first and @modules.first.path) ? File.basename(@modules.first.path) : '<unknown>')
		end
	end

	def self.new_api(lib, name, args, zero_is_err = true)
		args = args.delete(' ').split(//)
		retval = args.pop
		const_set(name, Win32API.new(lib, name, args, retval))
		define_method(name.downcase) { |*a|
			r = const_get(name).call(*a)
			if r == 0 and zero_is_err
				if $VERBOSE
				message = ' '*512
				errno = getlasterror()
				if formatmessage(FORMAT_MESSAGE_FROM_SYSTEM, nil, errno, 0, message, message.length, nil) == 0
					message = 'unknown error %x' % errno
				else
					message = message[0, message.index(0)] if message.index(0)
					message.chomp!
				end
				puts "WinAPI: Error in #{name}: #{message}"
				end
				nil
			else
				r
			end
		}
	end

	extend self	# any other way to dynamically create singleton methods ?
	
	# raw api function
	
	if defined? Win32API
	new_api 'kernel32', 'GetLastError', 'I', false
	new_api 'kernel32', 'FormatMessage', 'IPIIPIP I', false
	new_api 'kernel32', 'OpenProcess', 'III I'
	new_api 'kernel32', 'CloseHandle', 'I I'
	new_api 'kernel32', 'GetCurrentProcess', 'I'
	new_api 'kernel32', 'VirtualAllocEx', 'IIIII I'
	new_api 'kernel32', 'ReadProcessMemory', 'IIPIP I'
	new_api 'kernel32', 'WriteProcessMemory', 'IIPIP I'
	new_api 'advapi32', 'OpenProcessToken', 'IIP I'
	new_api 'advapi32', 'LookupPrivilegeValueA', 'PPP I'
	new_api 'advapi32', 'AdjustTokenPrivileges', 'IIPIPP I'
	new_api 'psapi', 'EnumProcesses', 'PIP I'
	new_api 'psapi', 'EnumProcessModules', 'IPIP I'
	new_api 'psapi', 'GetModuleFileNameEx', 'IIPI I'
	end
	
	
	# constants
	
	PROCESS_QUERY_INFORMATION = 0x400
	FORMAT_MESSAGE_FROM_SYSTEM = 0x1000
	PROCESS_VM_READ = 0x10
	TOKEN_ADJUST_PRIVILEGES = 0x20
	TOKEN_QUERY = 0x8
	SE_DEBUG_NAME = 'SeDebugPrivilege'
	SE_PRIVILEGE_ENABLED = 0x2
	PROCESS_ALL_ACCESS = 0x1FFFFF
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40


	# higher level functions
	
	# try to enable debug privilege in current process
	def self.get_debug_privilege
		htok = [0].pack('L')
		return if not openprocesstoken(getcurrentprocess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, htok)
		luid = [0, 0].pack('LL')
		return if not lookupprivilegevaluea(nil, SE_DEBUG_NAME, luid)

		# priv.PrivilegeCount = 1;
		# priv.Privileges[0].Luid = luid;
		# priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		priv = luid.unpack('LL').unshift(1).push(SE_PRIVILEGE_ENABLED).pack('LLLL')
		return if not adjusttokenprivileges(htok.unpack('L').first, 0, priv, priv.length, nil, nil)

		true
	end

	# returns an array of Processes, with pid/module listing
	def self.list_processes
		tab = ' '*4096
		int = [0].pack('L')
		return if not enumprocesses(tab, tab.length, int)
		pids = tab[0, int.unpack('L').first].unpack('L*')
		pids.map { |pid|
			pr = Process.new
			pr.pid = pid
			if handle = openprocess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid)
				mod = ' '*4096
				ret = [0].pack('L')
				if enumprocessmodules(handle, mod, mod.length, ret)
					pr.modules = []
					mod[0, ret.unpack('L').first].unpack('L*').each { |mod|
						path = ' ' * 512
						m = Process::Module.new
						m.addr = mod
						len = getmodulefilenameex(handle, mod, path, path.length)
						m.path = path[0, len]
						pr.modules << m
					}
				end
				closehandle(handle)
			end
			pr
		}
	end

	# returns the Process whose pid is name (numeric) or first module path includes name (string)
	def self.find_process(name)
		list_processes.find { |pr| pr.pid == name or (pr.modules.first.path.include? name.to_s rescue false) }
	end
end

class WindowsRemoteString < VirtualString
	def self.open_pid(pid, access = nil)
		if access
			handle = WinAPI.openprocess(access, 0, pid)
		else
			handle = WinAPI.openprocess(WinAPI::PROCESS_ALL_ACCESS, 0, pid)
			if not handle
				puts "cannot openprocess ALL_ACCESS pid #{pid}"
				handle = WinAPI.openprocess(WinAPI::PROCESS_VM_READ, 0, pid)
			end
		end
		raise "cannot open process #{pid}" if not handle

		new handle
	end

	attr_accessor :handle

	# returns a virtual string proxying the specified process memory range
	# reads are cached (4096 aligned bytes read at once)
	# writes are done directly (if handle has appropriate privileges)
	def initialize(handle, addr_start=0, length=0xffff_ffff)
		@handle = handle
		super(addr_start, length)
		# @curpage is overwritten every time by readprocmem
		@curpage = ' '*4096
	end

	def dup(addr = @addr_start, len = @length)
		self.class.new(@handle, addr, len)
	end

	def write_range(from, val)
		@invalid = true
		WinAPI.writeprocessmemory(@handle, @addr_start + from, val, val.length, nil)
	end

	def get_page(addr)
		@invalid = false
		@curstart = addr & 0xffff_f000
		WinAPI.readprocessmemory(@handle, @curstart, @curpage, 4096, 0)
	end

	def realstring
		super
		s = ' ' * @length
		WinAPI.readprocessmemory(@handle, @addr_start, s, @length, 0)
		s
	end
end
end
