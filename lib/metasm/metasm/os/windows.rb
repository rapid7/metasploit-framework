#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/os/main'
begin
require 'Win32API' if RUBY_PLATFORM =~ /mswin/i
rescue LoadError
end

module Metasm
module WinAPI
class << self
	def last_error_msg
		message = ' '*512
		errno = getlasterror()
		if formatmessage(FORMAT_MESSAGE_FROM_SYSTEM, nil, errno, 0, message, message.length, nil) == 0
			message = 'unknown error %x' % errno
		else
			message = message[0, message.index(?\0)] if message.index(?\0)
			message.chomp!
		end
		message
	end

	def new_api(lib, name, args, zero_is_err = true)
		args = args.delete(' ').split(//)
		retval = args.pop
		begin
			const_set(name, Win32API.new(lib, name, args, retval))
		rescue
			puts "no export #{name} found in #{lib}" if $VERBOSE
 			return
		end
		# booh this is fugly
		class << self ; self ; end.send(:define_method, name.downcase) { |*a|
			r = const_get(name).call(*a)
			if r == 0 and zero_is_err
				puts "WinAPI: Error in #{name}: #{last_error_msg}" if $VERBOSE
				nil
			else
				r
			end
		}
	end
end	# class << self

	if defined? Win32API
	new_api 'kernel32', 'CloseHandle', 'I I'
	new_api 'kernel32', 'ContinueDebugEvent', 'III I'
	new_api 'kernel32', 'CreateProcessA', 'PPPPIIPPPP I'
	new_api 'kernel32', 'CreateRemoteThread', 'IPIIIIP I'
	new_api 'kernel32', 'DebugActiveProcess', 'I I'
	new_api 'kernel32', 'DebugSetProcessKillOnExit', 'I I'
	new_api 'kernel32', 'FormatMessage', 'IPIIPIP I', false
	new_api 'kernel32', 'GetCurrentProcess', 'I'
	new_api 'kernel32', 'GetThreadContext', 'IP I'
	new_api 'kernel32', 'GetLastError', 'I', false
	new_api 'kernel32', 'GetProcessId', 'I I'
	new_api 'kernel32', 'OpenProcess', 'III I'
	new_api 'kernel32', 'ReadProcessMemory', 'IIPIP I', false	# only to disable "only part of ReadProcMem was completed"
	new_api 'kernel32', 'SetThreadContext', 'IP I'
	new_api 'kernel32', 'TerminateProcess', 'II I'
	new_api 'kernel32', 'VirtualAllocEx', 'IIIII I'
	new_api 'kernel32', 'WaitForDebugEvent', 'PI I'
	new_api 'kernel32', 'WriteProcessMemory', 'IIPIP I'
	new_api 'advapi32', 'OpenProcessToken', 'IIP I'
	new_api 'advapi32', 'LookupPrivilegeValueA', 'PPP I'
	new_api 'advapi32', 'AdjustTokenPrivileges', 'IIPIPP I'
	new_api 'psapi', 'EnumProcesses', 'PIP I'
	new_api 'psapi', 'EnumProcessModules', 'IPIP I'
	new_api 'psapi', 'GetModuleFileNameEx', 'IIPI I'
	new_api 'user32', 'PostMessageA', 'IIII I'
	new_api 'user32', 'MessageBoxA', 'IPPI I'
	end

	CONTEXT_i386 = 0x00010000
	CONTEXT86_CONTROL  = (CONTEXT_i386 | 0x0001) # SS:ESP, CS:EIP, FLAGS, EBP */
	CONTEXT86_INTEGER  = (CONTEXT_i386 | 0x0002) # EAX, EBX, ECX, EDX, ESI, EDI */
	CONTEXT86_SEGMENTS = (CONTEXT_i386 | 0x0004) # DS, ES, FS, GS */
	CONTEXT86_FLOATING_POINT  = (CONTEXT_i386 | 0x0008) # 387 state */
	CONTEXT86_DEBUG_REGISTERS = (CONTEXT_i386 | 0x0010) # DB 0-3,6,7 */
	CONTEXT86_FULL = (CONTEXT86_CONTROL | CONTEXT86_INTEGER | CONTEXT86_SEGMENTS)
	CREATE_PROCESS_DEBUG_EVENT = 3
	CREATE_THREAD_DEBUG_EVENT = 2
	DBG_CONTINUE = 0x00010002
	DBG_EXCEPTION_NOT_HANDLED = 0x80010001
	DEBUG_ONLY_THIS_PROCESS = 0x00000002
	DEBUG_PROCESS = 0x00000001
	EXCEPTION_DEBUG_EVENT = 1
	EXIT_PROCESS_DEBUG_EVENT = 5
	EXIT_THREAD_DEBUG_EVENT = 4
	FORMAT_MESSAGE_FROM_SYSTEM = 0x1000
	INFINITE = 0xffffffff
	LOAD_DLL_DEBUG_EVENT = 6
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	OUTPUT_DEBUG_STRING_EVENT = 8
	PAGE_READONLY = 0x02
	PAGE_EXECUTE_READWRITE = 0x40
	PROCESS_ALL_ACCESS = 0x1F0FFF
	PROCESS_QUERY_INFORMATION = 0x400
	PROCESS_VM_READ = 0x10
	PROCESS_VM_WRITE = 0x20
	RIP_EVENT = 9
	SE_DEBUG_NAME = 'SeDebugPrivilege'
	SE_PRIVILEGE_ENABLED = 0x2
	STATUS_ACCESS_VIOLATION = 0xC0000005
	STATUS_BREAKPOINT = 0x80000003
	STATUS_SINGLE_STEP = 0x80000004
	TOKEN_ADJUST_PRIVILEGES = 0x20
	TOKEN_QUERY = 0x8
	UNLOAD_DLL_DEBUG_EVENT = 7
end

class WinOS < OS
	class Process < Process
		# on-demand cached openprocess(ALL_ACCESS) handle
		def handle
			@handle ||= WinAPI.openprocess(WinAPI::PROCESS_ALL_ACCESS, 0, @pid)
		end
		def handle=(h) @handle = h end
		def memory
			@memory ||= WindowsRemoteString.new(handle)
		end
		def memory=(m) @memory = m end
	end

class << self
	# try to enable debug privilege in current process
	def get_debug_privilege
		htok = [0].pack('L')
		return if not WinAPI.openprocesstoken(WinAPI.getcurrentprocess(), WinAPI::TOKEN_ADJUST_PRIVILEGES | WinAPI::TOKEN_QUERY, htok)
		luid = [0, 0].pack('LL')
		return if not WinAPI.lookupprivilegevaluea(nil, WinAPI::SE_DEBUG_NAME, luid)

		# priv.PrivilegeCount = 1;
		# priv.Privileges[0].Luid = luid;
		# priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		priv = luid.unpack('LL').unshift(1).push(WinAPI::SE_PRIVILEGE_ENABLED).pack('LLLL')
		return if not WinAPI.adjusttokenprivileges(htok.unpack('L').first, 0, priv, 0, nil, nil)

		true
	end

	# returns an array of Processes, with pid/module listing
	def list_processes
		tab = ' '*4096
		int = [0].pack('L')
		return if not WinAPI.enumprocesses(tab, tab.length, int)
		pids = tab[0, int.unpack('L').first].unpack('L*')
		begin
		 # temporarily hide errors from openprocess(system_process) when VERBOSE
		 oldverb, $VERBOSE = $VERBOSE, false

		 pids.map { |pid|
			pr = Process.new
			pr.pid = pid
			if handle = WinAPI.openprocess(WinAPI::PROCESS_QUERY_INFORMATION | WinAPI::PROCESS_VM_READ, 0, pid)
				mods = ' '*4096
				ret = [0].pack('L')
				if WinAPI.enumprocessmodules(handle, mods, mods.length, ret)
					pr.modules = []
					mods[0, ret.unpack('L').first].unpack('L*').each { |mod|
						path = ' ' * 512
						m = Process::Module.new
						m.addr = mod
						len = WinAPI.getmodulefilenameex(handle, mod, path, path.length)
						m.path = path[0, len]
						pr.modules << m
					}
				end
				WinAPI.closehandle(handle)
			end
			pr
		 }
		ensure
			$VERBOSE = oldverb
		end
	end

	# Injects a shellcode into the memory space of targetproc
	# target is a WinOS::Process
	# shellcode may be a String (raw shellcode) or an EncodedData
	# With an EncodedData, unresolved relocations are solved using
	# exports of modules from the target address space ; also the
	# shellcode need not be position-independant.
	def inject_shellcode(target, shellcode)
		raise 'cannot open target memory' if not remote_mem = target.memory
#h1, h2 = remote_mem[0x301fd94, 4], remote_mem[0x301ffa8, 4]
#p h1.unpack('H*'), h2.unpack('H*')
#exit
		return if not injectaddr = WinAPI.virtualallocex(target.handle, 0, shellcode.length,
				WinAPI::MEM_COMMIT | WinAPI::MEM_RESERVE, WinAPI::PAGE_EXECUTE_READWRITE)
		puts 'remote buffer at %x' % injectaddr if $VERBOSE

		if shellcode.kind_of? EncodedData
			fixup_shellcode_relocs(shellcode, target, remote_mem)
			shellcode.fixup! shellcode.binding(injectaddr)
			r = shellcode.reloc.values.map { |r_| r_.target }
			raise "unresolved shellcode relocs #{r.join(', ')}" if not r.empty?
			shellcode = shellcode.data
		end

		# inject the shellcode
		remote_mem[injectaddr, shellcode.length] = shellcode

		injectaddr
	end

	def fixup_shellcode_relocs(shellcode, target, remote_mem)
		ext = shellcode.reloc_externals
		binding = {}
		while e = ext.pop
			next if binding[e]
			next if not lib = WindowsExports::EXPORT[e]	# XXX could scan all exports... LoadLibrary ftw
			next if not m = target.modules.find { |m_| m_.path.downcase.include? lib.downcase }
			lib = LoadedPE.load(remote_mem[m.addr, 0x1000_0000])
			lib.decode_header
			lib.decode_exports
			lib.export.exports.each { |e_|
				next if not e_.name or not e_.target
				binding[e_.name] = m.addr + lib.label_rva(e_.target)
			}
			shellcode.fixup! binding
		end
	end

	def createthread(target, startaddr)
		WinAPI.createremotethread(target.handle, 0, 0, startaddr, 0, 0, 0)
	end

	# calls inject_shellcode and createthread
	def inject_run_shellcode(target, shellcode)
		raise "failed to inject shellcode" if not addr = inject_shellcode(target, shellcode)
		createthread(target, addr)
	end
end	# class << self
end

class WindowsRemoteString < VirtualString
	def self.open_pid(pid, access = nil)
		if access
			handle = WinAPI.openprocess(access, 0, pid)
		else
			handle = WinAPI.openprocess(WinAPI::PROCESS_ALL_ACCESS, 0, pid)
			if not handle
				puts "cannot openprocess ALL_ACCESS pid #{pid}, try ro" if $VERBOSE
				handle = WinAPI.openprocess(WinAPI::PROCESS_VM_READ, 0, pid)
			end
		end
		raise "OpenProcess(#{pid}): #{WinAPI.last_error_msg}" if not handle

		new(handle)
	end

	attr_accessor :handle

	# returns a virtual string proxying the specified process memory range
	# reads are cached (4096 aligned bytes read at once)
	# writes are done directly (if handle has appropriate privileges)
	def initialize(handle, addr_start=0, length=0xffff_ffff)
		@handle = handle
		super(addr_start, length)
	end

	def dup(addr = @addr_start, len = @length)
		self.class.new(@handle, addr, len)
	end

	def rewrite_at(addr, data)
		WinAPI.writeprocessmemory(@handle, addr, data, data.length, nil)
	end

	def get_page(addr)
		page = 0.chr*4096
		WinAPI.readprocessmemory(@handle, addr, page, 4096, 0)
		page
	end

	def realstring
		s = 0.chr * @length
		WinAPI.readprocessmemory(@handle, @addr_start, s, @length, 0)
		s
	end
end

class WinDbg
	# pid => VirtualString
	attr_accessor :mem
	# pid => handle
	attr_accessor :hprocess
	# pid => (tid => handle)
	attr_accessor :hthread

	# creates a new debugger for target (a PID or an exe filename)
	def initialize(target, debug_children = false)
		@mem = {}
		@hprocess = {}
		@hthread = {}
		begin
			pid = Integer(target)
			WinAPI.debugactiveprocess(pid)
			WinAPI.debugsetprocesskillonexit(0) rescue nil
			@mem[pid] = WindowsRemoteString.open_pid(pid)
		rescue ArgumentError
			# *(int*)&startupinfo = sizeof(startupinfo);
			startupinfo = [17*[0].pack('L').length, *([0]*16)].pack('L*')
			processinfo = [0, 0, 0, 0].pack('L*')
			flags = WinAPI::DEBUG_PROCESS
			flags |= WinAPI::DEBUG_ONLY_THIS_PROCESS if not debug_children
			raise "CreateProcess: #{WinAPI.last_error_msg}" if not h = WinAPI.createprocessa(target, nil, nil, nil, 0, flags, nil, nil, startupinfo, processinfo)
			hprocess, hthread, pid, tid = processinfo.unpack('LLLL')
			WinAPI.closehandle(hthread)
			@mem[pid] = WindowsRemoteString.new(hprocess) # need @mem not empty (terminate condition of debugloop)
		end
	end

	# thread context (register values)
	class Context
		OFFSETS = {}
		OFFSETS[:ctxflags] = 0
		%w[dr0 dr1 dr2 dr3 dr6 dr7].each { |reg| OFFSETS[reg.to_sym] = OFFSETS.values.max + 4 }
		OFFSETS[:fpctrl] = OFFSETS.values.max + 4
		OFFSETS[:fpstatus] = OFFSETS.values.max + 4
		OFFSETS[:fptag] = OFFSETS.values.max + 4
		OFFSETS[:fperroffset] = OFFSETS.values.max + 4
		OFFSETS[:fperrselect] = OFFSETS.values.max + 4
		OFFSETS[:fpdataoffset] = OFFSETS.values.max + 4
		OFFSETS[:fpdataselect] = OFFSETS.values.max + 4
		OFFSETS[:fpregs] = OFFSETS.values.max + 4
		OFFSETS[:fpcr0] = OFFSETS.values.max + 80
		%w[gs fs es ds edi esi ebx edx ecx eax ebp eip cs eflags esp ss].each { |reg|
			OFFSETS[reg.to_sym] = OFFSETS.values.max + 4
		}

		attr_accessor :hthread, :ctx
		# retrieves the thread context
		def initialize(hthread, flags)
			@hthread = hthread
			@ctx = 0.chr * (OFFSETS.values.max + 4 + 512)
			set_val(:ctxflags, flags)
			WinAPI.getthreadcontext(@hthread, @ctx)
		end

		# returns the value of an unsigned int register
		def [](reg)
			@ctx[OFFSETS[reg], 4].unpack('L').first
		end

		# updates the value of an unsigned int register
		def []=(reg, value)
			set_val(reg, value)
			commit
		end

		# updates the local copy of the context, do not commit
		def set_val(reg, value)
			@ctx[OFFSETS[reg], 4] = [value].pack('L')
		end

		# updates the thread registers from the local copy
		def commit
			WinAPI.setthreadcontext(@hthread, @ctx)
		end
	end

	# returns the specified thread context
	def get_context(pid, tid, flags = WinAPI::CONTEXT86_FULL | WinAPI::CONTEXT86_DEBUG_REGISTERS)
		Context.new(@hthread[pid][tid], flags)
	end

	# classes for debug informations
	class ExceptionInfo
		attr_accessor :code, :flags, :recordptr, :addr, :nparam, :info, :firstchance
		def initialize(str)
			@code, @flags, @recordptr, @addr, @nparam, @info, @firstchance = str.unpack('LLLLLC60L')
		end
	end
	class CreateThreadInfo
		attr_accessor :hthread, :threadlocalbase, :startaddr
		def initialize(str)
			@hthread, @threadlocalbase, @startaddr = str.unpack('LLL')
		end
	end
	class CreateProcessInfo
		attr_accessor :hfile, :hprocess, :hthread, :imagebase, :debugfileoff, :debugfilesize, :threadlocalbase, :startaddr, :imagename, :unicode
		def initialize(str)
			@hfile, @hprocess, @hthread, @imagebase, @debugfileoff, @debugfilesize, @threadlocalbase,
				@startaddr, @imagename, @unicode = str.unpack('LLLLLLLLLS')
		end
	end
	class ExitThreadInfo
		attr_accessor :exitcode
		def initialize(str)
			@exitcode = *str.unpack('L')
		end
	end
	class ExitProcessInfo
		attr_accessor :exitcode
		def initialize(str)
			@exitcode = *str.unpack('L')
		end
	end
	class LoadDllInfo
		attr_accessor :hfile, :imagebase, :debugfileoff, :debugfilesize, :imagename, :unicode
		def initialize(str)
			@hfile, @imagebase, @debugfileoff, @debugfilesize, @imagename, @unicode = str.unpack('LLLLLS')
		end
	end
	class UnloadDllInfo
		attr_accessor :imagebase
		def initialize(str)
			@imagebase = *str.unpack('L')
		end
	end
	class OutputDebugStringInfo
		attr_accessor :ptr, :unicode, :length
		def initialize(str)
			@ptr, @unicode, @length = str.unpack('LSS')
		end
	end
	class RipInfo
		attr_accessor :error, :type
		def initialize(str)
			@error, @type = str.unpack('LL')
		end
	end

	# returns a string suitable for use as a debugevent structure
	def debugevent_alloc
		# on wxpsp2, debugevent is at most 24*uint
		([0]*30).pack('L*')
	end

	# waits for debug events
	# dispatches to the different handler_*
	# custom handlers should call the default version
	def debugloop
		debugevent = debugevent_alloc
		while not @mem.empty?
			return if not WinAPI.waitfordebugevent(debugevent, WinAPI::INFINITE)
			debugloop_step(debugevent)
		end
	end

	# handles one debug event
	# arg is a packed string containing a debugevent structure
	# usage:
	#  de = debugevent_alloc
	#  waitfordebugevent(de, <timeout>)
	#  debugloop_step(de)
	def debugloop_step(debugevent)
		code, pid, tid = debugevent.unpack('LLL')
		info = debugevent[[0,0,0].pack('LLL').length..-1]

		cont = \
		case code
		when WinAPI::EXCEPTION_DEBUG_EVENT
			handler_exception pid, tid, ExceptionInfo.new(info)
		when WinAPI::CREATE_PROCESS_DEBUG_EVENT
			handler_newprocess pid, tid, CreateProcessInfo.new(info)
		when WinAPI::CREATE_THREAD_DEBUG_EVENT
			handler_newthread pid, tid, CreateThreadInfo.new(info)
		when WinAPI::EXIT_PROCESS_DEBUG_EVENT
			handler_endprocess pid, tid, ExitProcessInfo.new(info)
		when WinAPI::EXIT_THREAD_DEBUG_EVENT
			handler_endthread pid, tid, ExitThreadInfo.new(info)
		when WinAPI::LOAD_DLL_DEBUG_EVENT
			handler_loaddll pid, tid, LoadDllInfo.new(info)
		when WinAPI::UNLOAD_DLL_DEBUG_EVENT
			handler_unloaddll pid, tid, UnloadDllInfo.new(info)
		when WinAPI::OUTPUT_DEBUG_STRING_EVENT
			handler_debugstring pid, tid, OutputDebugStringInfo.new(info)
		when WinAPI::RIP_EVENT
			handler_rip pid, tid, RipInfo.new(info)
		end

		WinAPI.continuedebugevent(pid, tid, cont)
	end

	def handler_exception(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} exception" if $DEBUG
		case info.code
		when WinAPI::STATUS_ACCESS_VIOLATION
			# fix fs bug in xpsp1
			ctx = get_context(pid, tid)
			if ctx[:fs] != 0x3b
				puts "wdbg: #{pid}:#{tid} fix fs bug" if $DEBUG
				ctx[:fs] = 0x3b
				return WinAPI::DBG_CONTINUE
			end
			WinAPI::DBG_EXCEPTION_NOT_HANDLED
		when WinAPI::STATUS_BREAKPOINT
			# we must ack ntdll interrupts on process start
			# but we should not mask process-generated exceptions by default..
			WinAPI::DBG_CONTINUE
		else
			WinAPI::DBG_EXCEPTION_NOT_HANDLED
		end
	end

	def handler_newprocess(pid, tid, info)
		str = read_str_indirect(pid, info.imagename, info.unicode)
		puts "wdbg: #{pid}:#{tid} new process #{str.inspect} at #{'0x%08X' % info.imagebase}" if $DEBUG
		@mem[pid] ||= WindowsRemoteString.new(info.hprocess)
		@hprocess[pid] = info.hprocess
		handler_newthread(pid, tid, info)
		WinAPI::DBG_CONTINUE
	end

	def handler_newthread(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} new thread at #{'0x%08X' % info.startaddr}" if $DEBUG
		@hthread[pid] ||= {}
		@hthread[pid][tid] = info.hthread
		WinAPI::DBG_CONTINUE
	end

	def handler_endprocess(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} process died" if $DEBUG
		@mem.delete pid
		WinAPI.closehandle @hprocess[pid]
		@hprocess.delete pid
		@hthread.delete pid
		WinAPI::DBG_CONTINUE
	end

	def handler_endthread(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} thread died" if $DEBUG
		WinAPI.closehandle @hthread[pid][tid]
		@hthread[pid].delete tid
		WinAPI::DBG_CONTINUE
	end

	def handler_loaddll(pid, tid, info)
		if $DEBUG
			dll = LoadedPE.load(@mem[pid][info.imagebase, 0x1000_0000])
			dll.decode_header
			dll.decode_exports
			str = (dll.export ? dll.export.libname : read_str_indirect(pid, info.imagename, info.unicode))
			puts "wdbg: #{pid}:#{tid} loaddll #{str.inspect} at #{'0x%08X' % info.imagebase}"
		end
		WinAPI::DBG_CONTINUE
	end

	def handler_unloaddll(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} unloaddll #{'0x%08X' % info.imagebase}"
		WinAPI::DBG_CONTINUE
	end

	def handler_debugstring(pid, tid, info)
		str = @mem[pid][@mem[pid][info.ptr, 4], info.length]
		str = str.unpack('S*').pack('C*') if info.unicode != 0
		puts "wdbg: #{pid}:#{tid} debugstring #{str.inspect}"
		WinAPI::DBG_CONTINUE
	end

	def handler_rip(pid, tid, info)
		puts "wdbg: #{pid}:#{tid} rip"
		WinAPI::DBG_CONTINUE
	end

	# reads a null-terminated string from a pointer in the remote address space
	def read_str_indirect(pid, ptr, unicode=0)
		return '' if not ptr or ptr == 0
		ptr = @mem[pid][ptr, 4].unpack('L').first
		str = @mem[pid][ptr, 512]
		str = str.unpack('S*').pack('C*') if unicode != 0
		str = str[0, str.index(?\0)] if str.index(?\0)
		str
	end
end

class WindowsExports
	# exported symbol name => exporting library name for common libraries
	# used by PE#autoimports
	EXPORT = {}
	# see samples/pe_listexports for the generator of this data
	data = <<EOL	# XXX libraries do not support __END__/DATA...
ADVAPI32
 I_ScGetCurrentGroupStateW A_SHAFinal A_SHAInit A_SHAUpdate AbortSystemShutdownA AbortSystemShutdownW AccessCheck AccessCheckAndAuditAlarmA
 AccessCheckAndAuditAlarmW AccessCheckByType AccessCheckByTypeAndAuditAlarmA AccessCheckByTypeAndAuditAlarmW AccessCheckByTypeResultList
 AccessCheckByTypeResultListAndAuditAlarmA AccessCheckByTypeResultListAndAuditAlarmByHandleA AccessCheckByTypeResultListAndAuditAlarmByHandleW
 AccessCheckByTypeResultListAndAuditAlarmW AddAccessAllowedAce AddAccessAllowedAceEx AddAccessAllowedObjectAce AddAccessDeniedAce AddAccessDeniedAceEx
 AddAccessDeniedObjectAce AddAce AddAuditAccessAce AddAuditAccessAceEx AddAuditAccessObjectAce AddUsersToEncryptedFile AdjustTokenGroups AdjustTokenPrivileges
 AllocateAndInitializeSid AllocateLocallyUniqueId AreAllAccessesGranted AreAnyAccessesGranted BackupEventLogA BackupEventLogW BuildExplicitAccessWithNameA
 BuildExplicitAccessWithNameW BuildImpersonateExplicitAccessWithNameA BuildImpersonateExplicitAccessWithNameW BuildImpersonateTrusteeA BuildImpersonateTrusteeW
 BuildSecurityDescriptorA BuildSecurityDescriptorW BuildTrusteeWithNameA BuildTrusteeWithNameW BuildTrusteeWithObjectsAndNameA BuildTrusteeWithObjectsAndNameW
 BuildTrusteeWithObjectsAndSidA BuildTrusteeWithObjectsAndSidW BuildTrusteeWithSidA BuildTrusteeWithSidW CancelOverlappedAccess ChangeServiceConfig2A
 ChangeServiceConfig2W ChangeServiceConfigA ChangeServiceConfigW CheckTokenMembership ClearEventLogA ClearEventLogW CloseCodeAuthzLevel CloseEncryptedFileRaw
 CloseEventLog CloseServiceHandle CloseTrace CommandLineFromMsiDescriptor ComputeAccessTokenFromCodeAuthzLevel ControlService ControlTraceA ControlTraceW
 ConvertAccessToSecurityDescriptorA ConvertAccessToSecurityDescriptorW ConvertSDToStringSDRootDomainA ConvertSDToStringSDRootDomainW
 ConvertSecurityDescriptorToAccessA ConvertSecurityDescriptorToAccessNamedA ConvertSecurityDescriptorToAccessNamedW ConvertSecurityDescriptorToAccessW
 ConvertSecurityDescriptorToStringSecurityDescriptorA ConvertSecurityDescriptorToStringSecurityDescriptorW ConvertSidToStringSidA ConvertSidToStringSidW
 ConvertStringSDToSDDomainA ConvertStringSDToSDDomainW ConvertStringSDToSDRootDomainA ConvertStringSDToSDRootDomainW
 ConvertStringSecurityDescriptorToSecurityDescriptorA ConvertStringSecurityDescriptorToSecurityDescriptorW ConvertStringSidToSidA ConvertStringSidToSidW
 ConvertToAutoInheritPrivateObjectSecurity CopySid CreateCodeAuthzLevel CreatePrivateObjectSecurity CreatePrivateObjectSecurityEx
 CreatePrivateObjectSecurityWithMultipleInheritance CreateProcessAsUserA CreateProcessAsUserSecure CreateProcessAsUserW CreateProcessWithLogonW
 CreateRestrictedToken CreateServiceA CreateServiceW CreateTraceInstanceId CreateWellKnownSid CredDeleteA CredDeleteW CredEnumerateA CredEnumerateW CredFree
 CredGetSessionTypes CredGetTargetInfoA CredGetTargetInfoW CredIsMarshaledCredentialA CredIsMarshaledCredentialW CredMarshalCredentialA CredMarshalCredentialW
 CredProfileLoaded CredReadA CredReadDomainCredentialsA CredReadDomainCredentialsW CredReadW CredRenameA CredRenameW CredUnmarshalCredentialA
 CredUnmarshalCredentialW CredWriteA CredWriteDomainCredentialsA CredWriteDomainCredentialsW CredWriteW CredpConvertCredential CredpConvertTargetInfo
 CredpDecodeCredential CredpEncodeCredential CryptAcquireContextA CryptAcquireContextW CryptContextAddRef CryptCreateHash CryptDecrypt CryptDeriveKey
 CryptDestroyHash CryptDestroyKey CryptDuplicateHash CryptDuplicateKey CryptEncrypt CryptEnumProviderTypesA CryptEnumProviderTypesW CryptEnumProvidersA
 CryptEnumProvidersW CryptExportKey CryptGenKey CryptGenRandom CryptGetDefaultProviderA CryptGetDefaultProviderW CryptGetHashParam CryptGetKeyParam
 CryptGetProvParam CryptGetUserKey CryptHashData CryptHashSessionKey CryptImportKey CryptReleaseContext CryptSetHashParam CryptSetKeyParam CryptSetProvParam
 CryptSetProviderA CryptSetProviderExA CryptSetProviderExW CryptSetProviderW CryptSignHashA CryptSignHashW CryptVerifySignatureA CryptVerifySignatureW
 DecryptFileA DecryptFileW DeleteAce DeleteService DeregisterEventSource DestroyPrivateObjectSecurity DuplicateEncryptionInfoFile DuplicateToken
 DuplicateTokenEx ElfBackupEventLogFileA ElfBackupEventLogFileW ElfChangeNotify ElfClearEventLogFileA ElfClearEventLogFileW ElfCloseEventLog
 ElfDeregisterEventSource ElfFlushEventLog ElfNumberOfRecords ElfOldestRecord ElfOpenBackupEventLogA ElfOpenBackupEventLogW ElfOpenEventLogA ElfOpenEventLogW
 ElfReadEventLogA ElfReadEventLogW ElfRegisterEventSourceA ElfRegisterEventSourceW ElfReportEventA ElfReportEventW EnableTrace EncryptFileA EncryptFileW
 EncryptedFileKeyInfo EncryptionDisable EnumDependentServicesA EnumDependentServicesW EnumServiceGroupW EnumServicesStatusA EnumServicesStatusExA
 EnumServicesStatusExW EnumServicesStatusW EnumerateTraceGuids EqualDomainSid EqualPrefixSid EqualSid FileEncryptionStatusA FileEncryptionStatusW
 FindFirstFreeAce FlushTraceA FlushTraceW FreeEncryptedFileKeyInfo FreeEncryptionCertificateHashList FreeInheritedFromArray FreeSid
 GetAccessPermissionsForObjectA GetAccessPermissionsForObjectW GetAce GetAclInformation GetAuditedPermissionsFromAclA GetAuditedPermissionsFromAclW
 GetCurrentHwProfileA GetCurrentHwProfileW GetEffectiveRightsFromAclA GetEffectiveRightsFromAclW GetEventLogInformation GetExplicitEntriesFromAclA
 GetExplicitEntriesFromAclW GetFileSecurityA GetFileSecurityW GetInformationCodeAuthzLevelW GetInformationCodeAuthzPolicyW GetInheritanceSourceA
 GetInheritanceSourceW GetKernelObjectSecurity GetLengthSid GetLocalManagedApplicationData GetLocalManagedApplications GetManagedApplicationCategories
 GetManagedApplications GetMultipleTrusteeA GetMultipleTrusteeOperationA GetMultipleTrusteeOperationW GetMultipleTrusteeW GetNamedSecurityInfoA
 GetNamedSecurityInfoExA GetNamedSecurityInfoExW GetNamedSecurityInfoW GetNumberOfEventLogRecords GetOldestEventLogRecord GetOverlappedAccessResults
 GetPrivateObjectSecurity GetSecurityDescriptorControl GetSecurityDescriptorDacl GetSecurityDescriptorGroup GetSecurityDescriptorLength
 GetSecurityDescriptorOwner GetSecurityDescriptorRMControl GetSecurityDescriptorSacl GetSecurityInfo GetSecurityInfoExA GetSecurityInfoExW
 GetServiceDisplayNameA GetServiceDisplayNameW GetServiceKeyNameA GetServiceKeyNameW GetSidIdentifierAuthority GetSidLengthRequired GetSidSubAuthority
 GetSidSubAuthorityCount GetTokenInformation GetTraceEnableFlags GetTraceEnableLevel GetTraceLoggerHandle GetTrusteeFormA GetTrusteeFormW GetTrusteeNameA
 GetTrusteeNameW GetTrusteeTypeA GetTrusteeTypeW GetUserNameA GetUserNameW GetWindowsAccountDomainSid I_ScIsSecurityProcess I_ScPnPGetServiceName
 I_ScSendTSMessage I_ScSetServiceBitsA I_ScSetServiceBitsW IdentifyCodeAuthzLevelW ImpersonateAnonymousToken ImpersonateLoggedOnUser ImpersonateNamedPipeClient
 ImpersonateSelf InitializeAcl InitializeSecurityDescriptor InitializeSid InitiateSystemShutdownA InitiateSystemShutdownExA InitiateSystemShutdownExW
 InitiateSystemShutdownW InstallApplication IsTextUnicode IsTokenRestricted IsTokenUntrusted IsValidAcl IsValidSecurityDescriptor IsValidSid IsWellKnownSid
 LockServiceDatabase LogonUserA LogonUserExA LogonUserExW LogonUserW LookupAccountNameA LookupAccountNameW LookupAccountSidA LookupAccountSidW
 LookupPrivilegeDisplayNameA LookupPrivilegeDisplayNameW LookupPrivilegeNameA LookupPrivilegeNameW LookupPrivilegeValueA LookupPrivilegeValueW
 LookupSecurityDescriptorPartsA LookupSecurityDescriptorPartsW LsaAddAccountRights LsaAddPrivilegesToAccount LsaClearAuditLog LsaClose LsaCreateAccount
 LsaCreateSecret LsaCreateTrustedDomain LsaCreateTrustedDomainEx LsaDelete LsaDeleteTrustedDomain LsaEnumerateAccountRights LsaEnumerateAccounts
 LsaEnumerateAccountsWithUserRight LsaEnumeratePrivileges LsaEnumeratePrivilegesOfAccount LsaEnumerateTrustedDomains LsaEnumerateTrustedDomainsEx LsaFreeMemory
 LsaGetQuotasForAccount LsaGetRemoteUserName LsaGetSystemAccessAccount LsaGetUserName LsaICLookupNames LsaICLookupNamesWithCreds LsaICLookupSids
 LsaICLookupSidsWithCreds LsaLookupNames2 LsaLookupNames LsaLookupPrivilegeDisplayName LsaLookupPrivilegeName LsaLookupPrivilegeValue LsaLookupSids
 LsaNtStatusToWinError LsaOpenAccount LsaOpenPolicy LsaOpenPolicySce LsaOpenSecret LsaOpenTrustedDomain LsaOpenTrustedDomainByName
 LsaQueryDomainInformationPolicy LsaQueryForestTrustInformation LsaQueryInfoTrustedDomain LsaQueryInformationPolicy LsaQuerySecret LsaQuerySecurityObject
 LsaQueryTrustedDomainInfo LsaQueryTrustedDomainInfoByName LsaRemoveAccountRights LsaRemovePrivilegesFromAccount LsaRetrievePrivateData
 LsaSetDomainInformationPolicy LsaSetForestTrustInformation LsaSetInformationPolicy LsaSetInformationTrustedDomain LsaSetQuotasForAccount LsaSetSecret
 LsaSetSecurityObject LsaSetSystemAccessAccount LsaSetTrustedDomainInfoByName LsaSetTrustedDomainInformation LsaStorePrivateData MD4Final MD4Init MD4Update
 MD5Final MD5Init MD5Update MSChapSrvChangePassword2 MSChapSrvChangePassword MakeAbsoluteSD2 MakeAbsoluteSD MakeSelfRelativeSD MapGenericMask
 NotifyBootConfigStatus NotifyChangeEventLog ObjectCloseAuditAlarmA ObjectCloseAuditAlarmW ObjectDeleteAuditAlarmA ObjectDeleteAuditAlarmW ObjectOpenAuditAlarmA
 ObjectOpenAuditAlarmW ObjectPrivilegeAuditAlarmA ObjectPrivilegeAuditAlarmW OpenBackupEventLogA OpenBackupEventLogW OpenEncryptedFileRawA OpenEncryptedFileRawW
 OpenEventLogA OpenEventLogW OpenProcessToken OpenSCManagerA OpenSCManagerW OpenServiceA OpenServiceW OpenThreadToken OpenTraceA OpenTraceW PrivilegeCheck
 PrivilegedServiceAuditAlarmA PrivilegedServiceAuditAlarmW ProcessIdleTasks ProcessTrace QueryAllTracesA QueryAllTracesW QueryRecoveryAgentsOnEncryptedFile
 QueryServiceConfig2A QueryServiceConfig2W QueryServiceConfigA QueryServiceConfigW QueryServiceLockStatusA QueryServiceLockStatusW QueryServiceObjectSecurity
 QueryServiceStatus QueryServiceStatusEx QueryTraceA QueryTraceW QueryUsersOnEncryptedFile QueryWindows31FilesMigration ReadEncryptedFileRaw ReadEventLogA
 ReadEventLogW RegCloseKey RegConnectRegistryA RegConnectRegistryW RegCreateKeyA RegCreateKeyExA RegCreateKeyExW RegCreateKeyW RegDeleteKeyA RegDeleteKeyW
 RegDeleteValueA RegDeleteValueW RegDisablePredefinedCache RegEnumKeyA RegEnumKeyExA RegEnumKeyExW RegEnumKeyW RegEnumValueA RegEnumValueW RegFlushKey
 RegGetKeySecurity RegLoadKeyA RegLoadKeyW RegNotifyChangeKeyValue RegOpenCurrentUser RegOpenKeyA RegOpenKeyExA RegOpenKeyExW RegOpenKeyW RegOpenUserClassesRoot
 RegOverridePredefKey RegQueryInfoKeyA RegQueryInfoKeyW RegQueryMultipleValuesA RegQueryMultipleValuesW RegQueryValueA RegQueryValueExA RegQueryValueExW
 RegQueryValueW RegReplaceKeyA RegReplaceKeyW RegRestoreKeyA RegRestoreKeyW RegSaveKeyA RegSaveKeyExA RegSaveKeyExW RegSaveKeyW RegSetKeySecurity RegSetValueA
 RegSetValueExA RegSetValueExW RegSetValueW RegUnLoadKeyA RegUnLoadKeyW RegisterEventSourceA RegisterEventSourceW RegisterIdleTask RegisterServiceCtrlHandlerA
 RegisterServiceCtrlHandlerExA RegisterServiceCtrlHandlerExW RegisterServiceCtrlHandlerW RegisterTraceGuidsA RegisterTraceGuidsW RemoveTraceCallback
 RemoveUsersFromEncryptedFile ReportEventA ReportEventW RevertToSelf SaferCloseLevel SaferComputeTokenFromLevel SaferCreateLevel SaferGetLevelInformation
 SaferGetPolicyInformation SaferIdentifyLevel SaferRecordEventLogEntry SaferSetLevelInformation SaferSetPolicyInformation SaferiChangeRegistryScope
 SaferiCompareTokenLevels SaferiIsExecutableFileType SaferiPopulateDefaultsInRegistry SaferiRecordEventLogEntry SaferiReplaceProcessThreadTokens
 SaferiSearchMatchingHashRules SetAclInformation SetEntriesInAccessListA SetEntriesInAccessListW SetEntriesInAclA SetEntriesInAclW SetEntriesInAuditListA
 SetEntriesInAuditListW SetFileSecurityA SetFileSecurityW SetInformationCodeAuthzLevelW SetInformationCodeAuthzPolicyW SetKernelObjectSecurity
 SetNamedSecurityInfoA SetNamedSecurityInfoExA SetNamedSecurityInfoExW SetNamedSecurityInfoW SetPrivateObjectSecurity SetPrivateObjectSecurityEx
 SetSecurityDescriptorControl SetSecurityDescriptorDacl SetSecurityDescriptorGroup SetSecurityDescriptorOwner SetSecurityDescriptorRMControl
 SetSecurityDescriptorSacl SetSecurityInfo SetSecurityInfoExA SetSecurityInfoExW SetServiceBits SetServiceObjectSecurity SetServiceStatus SetThreadToken
 SetTokenInformation SetTraceCallback SetUserFileEncryptionKey StartServiceA StartServiceCtrlDispatcherA StartServiceCtrlDispatcherW StartServiceW StartTraceA
 StartTraceW StopTraceA StopTraceW SynchronizeWindows31FilesAndWindowsNTRegistry SystemFunction001 SystemFunction002 SystemFunction003 SystemFunction004
 SystemFunction005 SystemFunction006 SystemFunction007 SystemFunction008 SystemFunction009 SystemFunction010 SystemFunction011 SystemFunction012
 SystemFunction013 SystemFunction014 SystemFunction015 SystemFunction016 SystemFunction017 SystemFunction018 SystemFunction019 SystemFunction020
 SystemFunction021 SystemFunction022 SystemFunction023 SystemFunction024 SystemFunction025 SystemFunction026 SystemFunction027 SystemFunction028
 SystemFunction029 SystemFunction030 SystemFunction031 SystemFunction032 SystemFunction033 SystemFunction034 SystemFunction035 SystemFunction036
 SystemFunction040 SystemFunction041 TraceEvent TraceEventInstance TraceMessage TraceMessageVa TreeResetNamedSecurityInfoA TreeResetNamedSecurityInfoW
 TrusteeAccessToObjectA TrusteeAccessToObjectW UninstallApplication UnlockServiceDatabase UnregisterIdleTask UnregisterTraceGuids UpdateTraceA UpdateTraceW
 WdmWmiServiceMain WmiCloseBlock WmiCloseTraceWithCursor WmiConvertTimestamp WmiDevInstToInstanceNameA WmiDevInstToInstanceNameW WmiEnumerateGuids
 WmiExecuteMethodA WmiExecuteMethodW WmiFileHandleToInstanceNameA WmiFileHandleToInstanceNameW WmiFreeBuffer WmiGetFirstTraceOffset WmiGetNextEvent
 WmiGetTraceHeader WmiMofEnumerateResourcesA WmiMofEnumerateResourcesW WmiNotificationRegistrationA WmiNotificationRegistrationW WmiOpenBlock
 WmiOpenTraceWithCursor WmiParseTraceEvent WmiQueryAllDataA WmiQueryAllDataMultipleA WmiQueryAllDataMultipleW WmiQueryAllDataW WmiQueryGuidInformation
 WmiQuerySingleInstanceA WmiQuerySingleInstanceMultipleA WmiQuerySingleInstanceMultipleW WmiQuerySingleInstanceW WmiReceiveNotificationsA
 WmiReceiveNotificationsW WmiSetSingleInstanceA WmiSetSingleInstanceW WmiSetSingleItemA WmiSetSingleItemW Wow64Win32ApiEntry WriteEncryptedFileRaw
WS2_32
 accept bind closesocket connect getpeername getsockname getsockopt htonl htons ioctlsocket inet_addr inet_ntoa listen ntohl ntohs recv recvfrom select send
 sendto setsockopt shutdown socket GetAddrInfoW GetNameInfoW WSApSetPostRoutine FreeAddrInfoW WPUCompleteOverlappedRequest WSAAccept WSAAddressToStringA
 WSAAddressToStringW WSACloseEvent WSAConnect WSACreateEvent WSADuplicateSocketA WSADuplicateSocketW WSAEnumNameSpaceProvidersA WSAEnumNameSpaceProvidersW
 WSAEnumNetworkEvents WSAEnumProtocolsA WSAEnumProtocolsW WSAEventSelect WSAGetOverlappedResult WSAGetQOSByName WSAGetServiceClassInfoA WSAGetServiceClassInfoW
 WSAGetServiceClassNameByClassIdA WSAGetServiceClassNameByClassIdW WSAHtonl WSAHtons gethostbyaddr gethostbyname getprotobyname getprotobynumber getservbyname
 getservbyport gethostname WSAInstallServiceClassA WSAInstallServiceClassW WSAIoctl WSAJoinLeaf WSALookupServiceBeginA WSALookupServiceBeginW
 WSALookupServiceEnd WSALookupServiceNextA WSALookupServiceNextW WSANSPIoctl WSANtohl WSANtohs WSAProviderConfigChange WSARecv WSARecvDisconnect WSARecvFrom
 WSARemoveServiceClass WSAResetEvent WSASend WSASendDisconnect WSASendTo WSASetEvent WSASetServiceA WSASetServiceW WSASocketA WSASocketW WSAStringToAddressA
 WSAStringToAddressW WSAWaitForMultipleEvents WSCDeinstallProvider WSCEnableNSProvider WSCEnumProtocols WSCGetProviderPath WSCInstallNameSpace
 WSCInstallProvider WSCUnInstallNameSpace WSCUpdateProvider WSCWriteNameSpaceOrder WSCWriteProviderOrder freeaddrinfo getaddrinfo getnameinfo WSAAsyncSelect
 WSAAsyncGetHostByAddr WSAAsyncGetHostByName WSAAsyncGetProtoByNumber WSAAsyncGetProtoByName WSAAsyncGetServByPort WSAAsyncGetServByName WSACancelAsyncRequest
 WSASetBlockingHook WSAUnhookBlockingHook WSAGetLastError WSASetLastError WSACancelBlockingCall WSAIsBlocking WSAStartup WSACleanup __WSAFDIsSet WEP
msvcrt
 _CIacos _CIasin _CIatan _CIatan2 _CIcos _CIcosh
 _CIexp _CIfmod _CIlog _CIlog10 _CIpow _CIsin _CIsinh _CIsqrt _CItan _CItanh _CxxThrowException _EH_prolog _Getdays _Getmonths _Gettnames _HUGE _Strftime
 _XcptFilter __CxxCallUnwindDtor __CxxDetectRethrow __CxxExceptionFilter __CxxFrameHandler __CxxLongjmpUnwind __CxxQueryExceptionSize
 __CxxRegisterExceptionObject __CxxUnregisterExceptionObject __DestructExceptionObject __RTCastToVoid __RTDynamicCast __RTtypeid __STRINGTOLD
 ___lc_codepage_func ___lc_handle_func ___mb_cur_max_func ___setlc_active_func ___unguarded_readlc_active_add_func __argc __argv __badioinfo __crtCompareStringA __crtCompareStringW __crtGetLocaleInfoW __crtGetStringTypeW __crtLCMapStringA __crtLCMapStringW __dllonexit __doserrno __fpecode __getmainargs __initenv
 __iob_func __isascii __iscsym __iscsymf __lc_codepage __lc_collate_cp __lc_handle __lconv_init __mb_cur_max __p___argc __p___argv __p___initenv
 __p___mb_cur_max __p___wargv __p___winitenv __p__acmdln __p__amblksiz __p__commode __p__daylight __p__dstbias __p__environ __p__fileinfo __p__fmode __p__iob
 __p__mbcasemap __p__mbctype __p__osver __p__pctype __p__pgmptr __p__pwctype __p__timezone __p__tzname __p__wcmdln __p__wenviron __p__winmajor __p__winminor
 __p__winver __p__wpgmptr __pctype_func __pioinfo __pxcptinfoptrs __set_app_type __setlc_active __setusermatherr __threadhandle __threadid __toascii __unDName
 __unDNameEx __unguarded_readlc_active __wargv __wcserror __wgetmainargs __winitenv _abnormal_termination _access _acmdln _adj_fdiv_m16i _adj_fdiv_m32
 _adj_fdiv_m32i _adj_fdiv_m64 _adj_fdiv_r _adj_fdivr_m16i _adj_fdivr_m32 _adj_fdivr_m32i _adj_fdivr_m64 _adj_fpatan _adj_fprem _adj_fprem1 _adj_fptan
 _adjust_fdiv _aexit_rtn _aligned_free _aligned_malloc _aligned_offset_malloc _aligned_offset_realloc _aligned_realloc _amsg_exit _assert _atodbl _atoi64
 _atoldbl _beep _beginthread _beginthreadex _c_exit _cabs _callnewh _cexit _cgets _cgetws _chdir _chdrive _chgsign _chkesp _chmod _chsize _clearfp _close
 _commit _commode _control87 _controlfp _copysign _cprintf _cputs _cputws _creat _cscanf _ctime64 _ctype _cwait _cwprintf _cwscanf _daylight _dstbias _dup _dup2 _ecvt _endthread _endthreadex _environ _eof _errno _except_handler2 _except_handler3 _execl _execle _execlp _execlpe _execv _execve _execvp _execvpe _exit
 _expand _fcloseall _fcvt _fdopen _fgetchar _fgetwchar _filbuf _fileinfo _filelength _filelengthi64 _fileno _findclose _findfirst _findfirst64 _findfirsti64
 _findnext _findnext64 _findnexti64 _finite _flsbuf _flushall _fmode _fpclass _fpieee_flt _fpreset _fputchar _fputwchar _fsopen _fstat _fstat64 _fstati64 _ftime _ftime64 _ftol _fullpath _futime _futime64 _gcvt _get_heap_handle _get_osfhandle _get_sbh_threshold _getch _getche _getcwd _getdcwd _getdiskfree
 _getdllprocaddr _getdrive _getdrives _getmaxstdio _getmbcp _getpid _getsystime _getw _getwch _getwche _getws _global_unwind2 _gmtime64 _heapadd _heapchk
 _heapmin _heapset _heapused _heapwalk _hypot _i64toa _i64tow _initterm _inp _inpd _inpw _iob _isatty _isctype _ismbbalnum _ismbbalpha _ismbbgraph _ismbbkalnum
 _ismbbkana _ismbbkprint _ismbbkpunct _ismbblead _ismbbprint _ismbbpunct _ismbbtrail _ismbcalnum _ismbcalpha _ismbcdigit _ismbcgraph _ismbchira _ismbckata
 _ismbcl0 _ismbcl1 _ismbcl2 _ismbclegal _ismbclower _ismbcprint _ismbcpunct _ismbcspace _ismbcsymbol _ismbcupper _ismbslead _ismbstrail _isnan _itoa _itow _j0
 _j1 _jn _kbhit _lfind _loaddll _local_unwind2 _localtime64 _lock _locking _logb _longjmpex _lrotl _lrotr _lsearch _lseek _lseeki64 _ltoa _ltow _makepath
 _mbbtombc _mbbtype _mbcasemap _mbccpy _mbcjistojms _mbcjmstojis _mbclen _mbctohira _mbctokata _mbctolower _mbctombb _mbctoupper _mbctype _mbsbtype _mbscat
 _mbschr _mbscmp _mbscoll _mbscpy _mbscspn _mbsdec _mbsdup _mbsicmp _mbsicoll _mbsinc _mbslen _mbslwr _mbsnbcat _mbsnbcmp _mbsnbcnt _mbsnbcoll _mbsnbcpy
 _mbsnbicmp _mbsnbicoll _mbsnbset _mbsncat _mbsnccnt _mbsncmp _mbsncoll _mbsncpy _mbsnextc _mbsnicmp _mbsnicoll _mbsninc _mbsnset _mbspbrk _mbsrchr _mbsrev
 _mbsset _mbsspn _mbsspnp _mbsstr _mbstok _mbstrlen _mbsupr _memccpy _memicmp _mkdir _mktemp _mktime64 _msize _nextafter _onexit _open _open_osfhandle
 _osplatform _osver _outp _outpd _outpw _pclose _pctype _pgmptr _pipe _popen _purecall _putch _putenv _putw _putwch _putws _pwctype _read _resetstkoflw _rmdir
 _rmtmp _rotl _rotr _safe_fdiv _safe_fdivr _safe_fprem _safe_fprem1 _scalb _scprintf _scwprintf _searchenv _seh_longjmp_unwind _set_SSE2_enable _set_error_mode
 _set_sbh_threshold _seterrormode _setjmp _setjmp3 _setmaxstdio _setmbcp _setmode _setsystime _sleep _snprintf _snscanf _snwprintf _snwscanf _sopen _spawnl
 _spawnle _spawnlp _spawnlpe _spawnv _spawnve _spawnvp _spawnvpe _splitpath _stat _stat64 _stati64 _statusfp _strcmpi _strdate _strdup _strerror _stricmp
 _stricoll _strlwr _strncoll _strnicmp _strnicoll _strnset _strrev _strset _strtime _strtoi64 _strtoui64 _strupr _swab _sys_errlist _sys_nerr _tell _telli64
 _tempnam _time64 _timezone _tolower _toupper _tzname _tzset _ui64toa _ui64tow _ultoa _ultow _umask _ungetch _ungetwch _unlink _unloaddll _unlock _utime
 _utime64 _vscprintf _vscwprintf _vsnprintf _vsnwprintf _waccess _wasctime _wchdir _wchmod _wcmdln _wcreat _wcsdup _wcserror _wcsicmp _wcsicoll _wcslwr
 _wcsncoll _wcsnicmp _wcsnicoll _wcsnset _wcsrev _wcsset _wcstoi64 _wcstoui64 _wcsupr _wctime _wctime64 _wenviron _wexecl _wexecle _wexeclp _wexeclpe _wexecv
 _wexecve _wexecvp _wexecvpe _wfdopen _wfindfirst _wfindfirst64 _wfindfirsti64 _wfindnext _wfindnext64 _wfindnexti64 _wfopen _wfreopen _wfsopen _wfullpath
 _wgetcwd _wgetdcwd _wgetenv _winmajor _winminor _winver _wmakepath _wmkdir _wmktemp _wopen _wperror _wpgmptr _wpopen _wputenv _wremove _wrename _write _wrmdir
 _wsearchenv _wsetlocale _wsopen _wspawnl _wspawnle _wspawnlp _wspawnlpe _wspawnv _wspawnve _wspawnvp _wspawnvpe _wsplitpath _wstat _wstat64 _wstati64 _wstrdate _wstrtime _wsystem _wtempnam _wtmpnam _wtof _wtoi _wtoi64 _wtol _wunlink _wutime _wutime64 _y0 _y1 _yn abort abs acos asctime asin atan atan2 atexit atof atoi
 atol bsearch calloc ceil clearerr clock cos cosh ctime difftime div exit exp fabs fclose feof ferror fflush fgetc fgetpos fgets fgetwc fgetws floor fmod fopen
 fprintf fputc fputs fputwc fputws fread free freopen frexp fscanf fseek fsetpos ftell fwprintf fwrite fwscanf getc getchar getenv gets getwc getwchar gmtime
 is_wctype isalnum isalpha iscntrl isdigit isgraph isleadbyte islower isprint ispunct isspace isupper iswalnum iswalpha iswascii iswcntrl iswctype iswdigit
 iswgraph iswlower iswprint iswpunct iswspace iswupper iswxdigit isxdigit labs ldexp ldiv localeconv localtime log log10 longjmp malloc mblen mbstowcs mbtowc
 memchr memcmp memcpy memmove memset mktime modf perror pow printf putc putchar puts putwc putwchar qsort raise rand realloc remove rename rewind scanf setbuf
 setlocale setvbuf signal sin sinh sprintf sqrt srand sscanf strcat strchr strcmp strcoll strcpy strcspn strerror strftime strlen strncat strncmp strncpy
 strpbrk strrchr strspn strstr strtod strtok strtol strtoul strxfrm swprintf swscanf system tan tanh time tmpfile tmpnam tolower toupper towlower towupper
 ungetc ungetwc vfprintf vfwprintf vprintf vsprintf vswprintf vwprintf wcscat wcschr wcscmp wcscoll wcscpy wcscspn wcsftime wcslen wcsncat wcsncmp wcsncpy
 wcspbrk wcsrchr wcsspn wcsstr wcstod wcstok wcstol wcstombs wcstoul wcsxfrm wctomb wprintf wscanf
comdlg32
 ChooseColorA ChooseColorW ChooseFontA ChooseFontW CommDlgExtendedError FindTextA FindTextW GetFileTitleA GetFileTitleW GetOpenFileNameA GetOpenFileNameW
 GetSaveFileNameA GetSaveFileNameW LoadAlterBitmap PageSetupDlgA PageSetupDlgW PrintDlgA PrintDlgExA PrintDlgExW PrintDlgW ReplaceTextA ReplaceTextW
 Ssync_ANSI_UNICODE_Struct_For_WOW WantArrows dwLBSubclass dwOKSubclass
PSAPI
 EmptyWorkingSet EnumDeviceDrivers EnumPageFilesA EnumPageFilesW EnumProcessModules EnumProcesses GetDeviceDriverBaseNameA GetDeviceDriverBaseNameW
 GetDeviceDriverFileNameA GetDeviceDriverFileNameW GetMappedFileNameA GetMappedFileNameW GetModuleBaseNameA GetModuleBaseNameW GetModuleFileNameExA
 GetModuleFileNameExW GetModuleInformation GetPerformanceInfo GetProcessImageFileNameA GetProcessImageFileNameW GetProcessMemoryInfo GetWsChanges
 InitializeProcessForWsWatch QueryWorkingSet
USER32
 ActivateKeyboardLayout AdjustWindowRect AdjustWindowRectEx AlignRects AllowForegroundActivation AllowSetForegroundWindow AnimateWindow AnyPopup AppendMenuA
 AppendMenuW ArrangeIconicWindows AttachThreadInput BeginDeferWindowPos BeginPaint BlockInput BringWindowToTop BroadcastSystemMessage BroadcastSystemMessageA
 BroadcastSystemMessageExA BroadcastSystemMessageExW BroadcastSystemMessageW BuildReasonArray CalcMenuBar CallMsgFilter CallMsgFilterA CallMsgFilterW
 CallNextHookEx CallWindowProcA CallWindowProcW CascadeChildWindows CascadeWindows ChangeClipboardChain ChangeDisplaySettingsA ChangeDisplaySettingsExA
 ChangeDisplaySettingsExW ChangeDisplaySettingsW ChangeMenuA ChangeMenuW CharLowerA CharLowerBuffA CharLowerBuffW CharLowerW CharNextA CharNextExA CharNextW
 CharPrevA CharPrevExA CharPrevW CharToOemA CharToOemBuffA CharToOemBuffW CharToOemW CharUpperA CharUpperBuffA CharUpperBuffW CharUpperW CheckDlgButton
 CheckMenuItem CheckMenuRadioItem CheckRadioButton ChildWindowFromPoint ChildWindowFromPointEx CliImmSetHotKey ClientThreadSetup ClientToScreen ClipCursor
 CloseClipboard CloseDesktop CloseWindow CloseWindowStation CopyAcceleratorTableA CopyAcceleratorTableW CopyIcon CopyImage CopyRect CountClipboardFormats
 CreateAcceleratorTableA CreateAcceleratorTableW CreateCaret CreateCursor CreateDesktopA CreateDesktopW CreateDialogIndirectParamA CreateDialogIndirectParamAorW
 CreateDialogIndirectParamW CreateDialogParamA CreateDialogParamW CreateIcon CreateIconFromResource CreateIconFromResourceEx CreateIconIndirect CreateMDIWindowA
 CreateMDIWindowW CreateMenu CreatePopupMenu CreateSystemThreads CreateWindowExA CreateWindowExW CreateWindowStationA CreateWindowStationW
 CsrBroadcastSystemMessageExW CtxInitUser32 DdeAbandonTransaction DdeAccessData DdeAddData DdeClientTransaction DdeCmpStringHandles DdeConnect DdeConnectList
 DdeCreateDataHandle DdeCreateStringHandleA DdeCreateStringHandleW DdeDisconnect DdeDisconnectList DdeEnableCallback DdeFreeDataHandle DdeFreeStringHandle
 DdeGetData DdeGetLastError DdeGetQualityOfService DdeImpersonateClient DdeInitializeA DdeInitializeW DdeKeepStringHandle DdeNameService DdePostAdvise
 DdeQueryConvInfo DdeQueryNextServer DdeQueryStringA DdeQueryStringW DdeReconnect DdeSetQualityOfService DdeSetUserHandle DdeUnaccessData DdeUninitialize
 DefDlgProcA DefDlgProcW DefFrameProcA DefFrameProcW DefMDIChildProcA DefMDIChildProcW DefRawInputProc DefWindowProcA DefWindowProcW DeferWindowPos DeleteMenu
 DeregisterShellHookWindow DestroyAcceleratorTable DestroyCaret DestroyCursor DestroyIcon DestroyMenu DestroyReasons DestroyWindow DeviceEventWorker
 DialogBoxIndirectParamA DialogBoxIndirectParamAorW DialogBoxIndirectParamW DialogBoxParamA DialogBoxParamW DisableProcessWindowsGhosting DispatchMessageA
 DispatchMessageW DisplayExitWindowsWarnings DlgDirListA DlgDirListComboBoxA DlgDirListComboBoxW DlgDirListW DlgDirSelectComboBoxExA DlgDirSelectComboBoxExW
 DlgDirSelectExA DlgDirSelectExW DragDetect DragObject DrawAnimatedRects DrawCaption DrawCaptionTempA DrawCaptionTempW DrawEdge DrawFocusRect DrawFrame
 DrawFrameControl DrawIcon DrawIconEx DrawMenuBar DrawMenuBarTemp DrawStateA DrawStateW DrawTextA DrawTextExA DrawTextExW DrawTextW EditWndProc EmptyClipboard
 EnableMenuItem EnableScrollBar EnableWindow EndDeferWindowPos EndDialog EndMenu EndPaint EndTask EnterReaderModeHelper EnumChildWindows EnumClipboardFormats
 EnumDesktopWindows EnumDesktopsA EnumDesktopsW EnumDisplayDevicesA EnumDisplayDevicesW EnumDisplayMonitors EnumDisplaySettingsA EnumDisplaySettingsExA
 EnumDisplaySettingsExW EnumDisplaySettingsW EnumPropsA EnumPropsExA EnumPropsExW EnumPropsW EnumThreadWindows EnumWindowStationsA EnumWindowStationsW
 EnumWindows EqualRect ExcludeUpdateRgn ExitWindowsEx FillRect FindWindowA FindWindowExA FindWindowExW FindWindowW FlashWindow FlashWindowEx FrameRect
 FreeDDElParam GetActiveWindow GetAltTabInfo GetAltTabInfoA GetAltTabInfoW GetAncestor GetAppCompatFlags2 GetAppCompatFlags GetAsyncKeyState GetCapture
 GetCaretBlinkTime GetCaretPos GetClassInfoA GetClassInfoExA GetClassInfoExW GetClassInfoW GetClassLongA GetClassLongW GetClassNameA GetClassNameW GetClassWord
 GetClientRect GetClipCursor GetClipboardData GetClipboardFormatNameA GetClipboardFormatNameW GetClipboardOwner GetClipboardSequenceNumber GetClipboardViewer
 GetComboBoxInfo GetCursor GetCursorFrameInfo GetCursorInfo GetCursorPos GetDC GetDCEx GetDesktopWindow GetDialogBaseUnits GetDlgCtrlID GetDlgItem GetDlgItemInt
 GetDlgItemTextA GetDlgItemTextW GetDoubleClickTime GetFocus GetForegroundWindow GetGUIThreadInfo GetGuiResources GetIconInfo GetInputDesktop GetInputState
 GetInternalWindowPos GetKBCodePage GetKeyNameTextA GetKeyNameTextW GetKeyState GetKeyboardLayout GetKeyboardLayoutList GetKeyboardLayoutNameA
 GetKeyboardLayoutNameW GetKeyboardState GetKeyboardType GetLastActivePopup GetLastInputInfo GetLayeredWindowAttributes GetListBoxInfo GetMenu GetMenuBarInfo
 GetMenuCheckMarkDimensions GetMenuContextHelpId GetMenuDefaultItem GetMenuInfo GetMenuItemCount GetMenuItemID GetMenuItemInfoA GetMenuItemInfoW GetMenuItemRect
 GetMenuState GetMenuStringA GetMenuStringW GetMessageA GetMessageExtraInfo GetMessagePos GetMessageTime GetMessageW GetMonitorInfoA GetMonitorInfoW
 GetMouseMovePointsEx GetNextDlgGroupItem GetNextDlgTabItem GetOpenClipboardWindow GetParent GetPriorityClipboardFormat GetProcessDefaultLayout
 GetProcessWindowStation GetProgmanWindow GetPropA GetPropW GetQueueStatus GetRawInputBuffer GetRawInputData GetRawInputDeviceInfoA GetRawInputDeviceInfoW
 GetRawInputDeviceList GetReasonTitleFromReasonCode GetRegisteredRawInputDevices GetScrollBarInfo GetScrollInfo GetScrollPos GetScrollRange GetShellWindow
 GetSubMenu GetSysColor GetSysColorBrush GetSystemMenu GetSystemMetrics GetTabbedTextExtentA GetTabbedTextExtentW GetTaskmanWindow GetThreadDesktop
 GetTitleBarInfo GetTopWindow GetUpdateRect GetUpdateRgn GetUserObjectInformationA GetUserObjectInformationW GetUserObjectSecurity GetWinStationInfo GetWindow
 GetWindowContextHelpId GetWindowDC GetWindowInfo GetWindowLongA GetWindowLongW GetWindowModuleFileName GetWindowModuleFileNameA GetWindowModuleFileNameW
 GetWindowPlacement GetWindowRect GetWindowRgn GetWindowRgnBox GetWindowTextA GetWindowTextLengthA GetWindowTextLengthW GetWindowTextW GetWindowThreadProcessId
 GetWindowWord GrayStringA GrayStringW HideCaret HiliteMenuItem IMPGetIMEA IMPGetIMEW IMPQueryIMEA IMPQueryIMEW IMPSetIMEA IMPSetIMEW ImpersonateDdeClientWindow
 InSendMessage InSendMessageEx InflateRect InitializeLpkHooks InitializeWin32EntryTable InsertMenuA InsertMenuItemA InsertMenuItemW InsertMenuW
 InternalGetWindowText IntersectRect InvalidateRect InvalidateRgn InvertRect IsCharAlphaA IsCharAlphaNumericA IsCharAlphaNumericW IsCharAlphaW IsCharLowerA
 IsCharLowerW IsCharUpperA IsCharUpperW IsChild IsClipboardFormatAvailable IsDialogMessage IsDialogMessageA IsDialogMessageW IsDlgButtonChecked IsGUIThread
 IsHungAppWindow IsIconic IsMenu IsRectEmpty IsServerSideWindow IsWinEventHookInstalled IsWindow IsWindowEnabled IsWindowInDestroy IsWindowUnicode
 IsWindowVisible IsZoomed KillSystemTimer KillTimer LoadAcceleratorsA LoadAcceleratorsW LoadBitmapA LoadBitmapW LoadCursorA LoadCursorFromFileA
 LoadCursorFromFileW LoadCursorW LoadIconA LoadIconW LoadImageA LoadImageW LoadKeyboardLayoutA LoadKeyboardLayoutEx LoadKeyboardLayoutW LoadLocalFonts LoadMenuA
 LoadMenuIndirectA LoadMenuIndirectW LoadMenuW LoadRemoteFonts LoadStringA LoadStringW LockSetForegroundWindow LockWindowStation LockWindowUpdate
 LockWorkStation LookupIconIdFromDirectory LookupIconIdFromDirectoryEx MBToWCSEx MB_GetString MapDialogRect MapVirtualKeyA MapVirtualKeyExA MapVirtualKeyExW
 MapVirtualKeyW MapWindowPoints MenuItemFromPoint MenuWindowProcA MenuWindowProcW MessageBeep MessageBoxA MessageBoxExA MessageBoxExW MessageBoxIndirectA
 MessageBoxIndirectW MessageBoxTimeoutA MessageBoxTimeoutW MessageBoxW ModifyMenuA ModifyMenuW MonitorFromPoint MonitorFromRect MonitorFromWindow MoveWindow
 MsgWaitForMultipleObjects MsgWaitForMultipleObjectsEx NotifyWinEvent OemKeyScan OemToCharA OemToCharBuffA OemToCharBuffW OemToCharW OffsetRect OpenClipboard
 OpenDesktopA OpenDesktopW OpenIcon OpenInputDesktop OpenWindowStationA OpenWindowStationW PackDDElParam PaintDesktop PaintMenuBar PeekMessageA PeekMessageW
 PostMessageA PostMessageW PostQuitMessage PostThreadMessageA PostThreadMessageW PrintWindow PrivateExtractIconExA PrivateExtractIconExW PrivateExtractIconsA
 PrivateExtractIconsW PrivateSetDbgTag PrivateSetRipFlags PtInRect QuerySendMessage QueryUserCounters RealChildWindowFromPoint RealGetWindowClass
 RealGetWindowClassA RealGetWindowClassW ReasonCodeNeedsBugID ReasonCodeNeedsComment RecordShutdownReason RedrawWindow RegisterClassA RegisterClassExA
 RegisterClassExW RegisterClassW RegisterClipboardFormatA RegisterClipboardFormatW RegisterDeviceNotificationA RegisterDeviceNotificationW RegisterHotKey
 RegisterLogonProcess RegisterMessagePumpHook RegisterRawInputDevices RegisterServicesProcess RegisterShellHookWindow RegisterSystemThread RegisterTasklist
 RegisterUserApiHook RegisterWindowMessageA RegisterWindowMessageW ReleaseCapture ReleaseDC RemoveMenu RemovePropA RemovePropW ReplyMessage ResolveDesktopForWOW
 ReuseDDElParam ScreenToClient ScrollChildren ScrollDC ScrollWindow ScrollWindowEx SendDlgItemMessageA SendDlgItemMessageW SendIMEMessageExA SendIMEMessageExW
 SendInput SendMessageA SendMessageCallbackA SendMessageCallbackW SendMessageTimeoutA SendMessageTimeoutW SendMessageW SendNotifyMessageA SendNotifyMessageW
 SetActiveWindow SetCapture SetCaretBlinkTime SetCaretPos SetClassLongA SetClassLongW SetClassWord SetClipboardData SetClipboardViewer SetConsoleReserveKeys
 SetCursor SetCursorContents SetCursorPos SetDebugErrorLevel SetDeskWallpaper SetDlgItemInt SetDlgItemTextA SetDlgItemTextW SetDoubleClickTime SetFocus
 SetForegroundWindow SetInternalWindowPos SetKeyboardState SetLastErrorEx SetLayeredWindowAttributes SetLogonNotifyWindow SetMenu SetMenuContextHelpId
 SetMenuDefaultItem SetMenuInfo SetMenuItemBitmaps SetMenuItemInfoA SetMenuItemInfoW SetMessageExtraInfo SetMessageQueue SetParent SetProcessDefaultLayout
 SetProcessWindowStation SetProgmanWindow SetPropA SetPropW SetRect SetRectEmpty SetScrollInfo SetScrollPos SetScrollRange SetShellWindow SetShellWindowEx
 SetSysColors SetSysColorsTemp SetSystemCursor SetSystemMenu SetSystemTimer SetTaskmanWindow SetThreadDesktop SetTimer SetUserObjectInformationA
 SetUserObjectInformationW SetUserObjectSecurity SetWinEventHook SetWindowContextHelpId SetWindowLongA SetWindowLongW SetWindowPlacement SetWindowPos
 SetWindowRgn SetWindowStationUser SetWindowTextA SetWindowTextW SetWindowWord SetWindowsHookA SetWindowsHookExA SetWindowsHookExW SetWindowsHookW ShowCaret
 ShowCursor ShowOwnedPopups ShowScrollBar ShowStartGlass ShowWindow ShowWindowAsync SoftModalMessageBox SubtractRect SwapMouseButton SwitchDesktop
 SwitchToThisWindow SystemParametersInfoA SystemParametersInfoW TabbedTextOutA TabbedTextOutW TileChildWindows TileWindows ToAscii ToAsciiEx ToUnicode
 ToUnicodeEx TrackMouseEvent TrackPopupMenu TrackPopupMenuEx TranslateAccelerator TranslateAcceleratorA TranslateAcceleratorW TranslateMDISysAccel
 TranslateMessage TranslateMessageEx UnhookWinEvent UnhookWindowsHook UnhookWindowsHookEx UnionRect UnloadKeyboardLayout UnlockWindowStation UnpackDDElParam
 UnregisterClassA UnregisterClassW UnregisterDeviceNotification UnregisterHotKey UnregisterMessagePumpHook UnregisterUserApiHook UpdateLayeredWindow
 UpdatePerUserSystemParameters UpdateWindow User32InitializeImmEntryTable UserClientDllInitialize UserHandleGrantAccess UserLpkPSMTextOut UserLpkTabbedTextOut
 UserRealizePalette UserRegisterWowHandlers VRipOutput VTagOutput ValidateRect ValidateRgn VkKeyScanA VkKeyScanExA VkKeyScanExW VkKeyScanW WCSToMBEx
 WINNLSEnableIME WINNLSGetEnableStatus WINNLSGetIMEHotkey WaitForInputIdle WaitMessage Win32PoolAllocationStats WinHelpA WinHelpW WindowFromDC WindowFromPoint
 keybd_event mouse_event wsprintfA wsprintfW wvsprintfA wvsprintfW
KERNEL32
 ActivateActCtx AddAtomA AddAtomW AddConsoleAliasA AddConsoleAliasW AddLocalAlternateComputerNameA AddLocalAlternateComputerNameW AddRefActCtx
 AddVectoredExceptionHandler AllocConsole AllocateUserPhysicalPages AreFileApisANSI AssignProcessToJobObject AttachConsole BackupRead BackupSeek BackupWrite
 BaseCheckAppcompatCache BaseCleanupAppcompatCache BaseCleanupAppcompatCacheSupport BaseDumpAppcompatCache BaseFlushAppcompatCache BaseInitAppcompatCache
 BaseInitAppcompatCacheSupport BaseProcessInitPostImport BaseQueryModuleData BaseUpdateAppcompatCache BasepCheckWinSaferRestrictions Beep BeginUpdateResourceA
 BeginUpdateResourceW BindIoCompletionCallback BuildCommDCBA BuildCommDCBAndTimeoutsA BuildCommDCBAndTimeoutsW BuildCommDCBW CallNamedPipeA CallNamedPipeW
 CancelDeviceWakeupRequest CancelIo CancelTimerQueueTimer CancelWaitableTimer ChangeTimerQueueTimer CheckNameLegalDOS8Dot3A CheckNameLegalDOS8Dot3W
 CheckRemoteDebuggerPresent ClearCommBreak ClearCommError CloseConsoleHandle CloseHandle CloseProfileUserMapping CmdBatNotification CommConfigDialogA
 CommConfigDialogW CompareFileTime CompareStringA CompareStringW ConnectNamedPipe ConsoleMenuControl ContinueDebugEvent ConvertDefaultLocale
 ConvertFiberToThread ConvertThreadToFiber CopyFileA CopyFileExA CopyFileExW CopyFileW CopyLZFile CreateActCtxA CreateActCtxW CreateConsoleScreenBuffer
 CreateDirectoryA CreateDirectoryExA CreateDirectoryExW CreateDirectoryW CreateEventA CreateEventW CreateFiber CreateFiberEx CreateFileA CreateFileMappingA
 CreateFileMappingW CreateFileW CreateHardLinkA CreateHardLinkW CreateIoCompletionPort CreateJobObjectA CreateJobObjectW CreateJobSet CreateMailslotA
 CreateMailslotW CreateMemoryResourceNotification CreateMutexA CreateMutexW CreateNamedPipeA CreateNamedPipeW CreateNlsSecurityDescriptor CreatePipe
 CreateProcessA CreateProcessInternalA CreateProcessInternalW CreateProcessInternalWSecure CreateProcessW CreateRemoteThread CreateSemaphoreA CreateSemaphoreW
 CreateSocketHandle CreateTapePartition CreateThread CreateTimerQueue CreateTimerQueueTimer CreateToolhelp32Snapshot CreateVirtualBuffer CreateWaitableTimerA
 CreateWaitableTimerW DeactivateActCtx DebugActiveProcess DebugActiveProcessStop DebugBreak DebugBreakProcess DebugSetProcessKillOnExit DecodePointer
 DecodeSystemPointer DefineDosDeviceA DefineDosDeviceW DelayLoadFailureHook DeleteAtom DeleteCriticalSection DeleteFiber DeleteFileA DeleteFileW
 DeleteTimerQueue DeleteTimerQueueEx DeleteTimerQueueTimer DeleteVolumeMountPointA DeleteVolumeMountPointW DeviceIoControl DisableThreadLibraryCalls
 DisconnectNamedPipe DnsHostnameToComputerNameA DnsHostnameToComputerNameW DosDateTimeToFileTime DosPathToSessionPathA DosPathToSessionPathW
 DuplicateConsoleHandle DuplicateHandle EncodePointer EncodeSystemPointer EndUpdateResourceA EndUpdateResourceW EnterCriticalSection EnumCalendarInfoA
 EnumCalendarInfoExA EnumCalendarInfoExW EnumCalendarInfoW EnumDateFormatsA EnumDateFormatsExA EnumDateFormatsExW EnumDateFormatsW EnumLanguageGroupLocalesA
 EnumLanguageGroupLocalesW EnumResourceLanguagesA EnumResourceLanguagesW EnumResourceNamesA EnumResourceNamesW EnumResourceTypesA EnumResourceTypesW
 EnumSystemCodePagesA EnumSystemCodePagesW EnumSystemGeoID EnumSystemLanguageGroupsA EnumSystemLanguageGroupsW EnumSystemLocalesA EnumSystemLocalesW
 EnumTimeFormatsA EnumTimeFormatsW EnumUILanguagesA EnumUILanguagesW EnumerateLocalComputerNamesA EnumerateLocalComputerNamesW EraseTape EscapeCommFunction
 ExitProcess ExitThread ExitVDM ExpandEnvironmentStringsA ExpandEnvironmentStringsW ExpungeConsoleCommandHistoryA ExpungeConsoleCommandHistoryW
 ExtendVirtualBuffer FatalAppExitA FatalAppExitW FatalExit FileTimeToDosDateTime FileTimeToLocalFileTime FileTimeToSystemTime FillConsoleOutputAttribute
 FillConsoleOutputCharacterA FillConsoleOutputCharacterW FindActCtxSectionGuid FindActCtxSectionStringA FindActCtxSectionStringW FindAtomA FindAtomW FindClose
 FindCloseChangeNotification FindFirstChangeNotificationA FindFirstChangeNotificationW FindFirstFileA FindFirstFileExA FindFirstFileExW FindFirstFileW
 FindFirstVolumeA FindFirstVolumeMountPointA FindFirstVolumeMountPointW FindFirstVolumeW FindNextChangeNotification FindNextFileA FindNextFileW FindNextVolumeA
 FindNextVolumeMountPointA FindNextVolumeMountPointW FindNextVolumeW FindResourceA FindResourceExA FindResourceExW FindResourceW FindVolumeClose
 FindVolumeMountPointClose FlushConsoleInputBuffer FlushFileBuffers FlushInstructionCache FlushViewOfFile FoldStringA FoldStringW FormatMessageA FormatMessageW
 FreeConsole FreeEnvironmentStringsA FreeEnvironmentStringsW FreeLibrary FreeLibraryAndExitThread FreeResource FreeUserPhysicalPages FreeVirtualBuffer
 GenerateConsoleCtrlEvent GetACP GetAtomNameA GetAtomNameW GetBinaryType GetBinaryTypeA GetBinaryTypeW GetCPFileNameFromRegistry GetCPInfo GetCPInfoExA
 GetCPInfoExW GetCalendarInfoA GetCalendarInfoW GetComPlusPackageInstallStatus GetCommConfig GetCommMask GetCommModemStatus GetCommProperties GetCommState
 GetCommTimeouts GetCommandLineA GetCommandLineW GetCompressedFileSizeA GetCompressedFileSizeW GetComputerNameA GetComputerNameExA GetComputerNameExW
 GetComputerNameW GetConsoleAliasA GetConsoleAliasExesA GetConsoleAliasExesLengthA GetConsoleAliasExesLengthW GetConsoleAliasExesW GetConsoleAliasW
 GetConsoleAliasesA GetConsoleAliasesLengthA GetConsoleAliasesLengthW GetConsoleAliasesW GetConsoleCP GetConsoleCharType GetConsoleCommandHistoryA
 GetConsoleCommandHistoryLengthA GetConsoleCommandHistoryLengthW GetConsoleCommandHistoryW GetConsoleCursorInfo GetConsoleCursorMode GetConsoleDisplayMode
 GetConsoleFontInfo GetConsoleFontSize GetConsoleHardwareState GetConsoleInputExeNameA GetConsoleInputExeNameW GetConsoleInputWaitHandle
 GetConsoleKeyboardLayoutNameA GetConsoleKeyboardLayoutNameW GetConsoleMode GetConsoleNlsMode GetConsoleOutputCP GetConsoleProcessList
 GetConsoleScreenBufferInfo GetConsoleSelectionInfo GetConsoleTitleA GetConsoleTitleW GetConsoleWindow GetCurrencyFormatA GetCurrencyFormatW GetCurrentActCtx
 GetCurrentConsoleFont GetCurrentDirectoryA GetCurrentDirectoryW GetCurrentProcess GetCurrentProcessId GetCurrentThread GetCurrentThreadId GetDateFormatA
 GetDateFormatW GetDefaultCommConfigA GetDefaultCommConfigW GetDefaultSortkeySize GetDevicePowerState GetDiskFreeSpaceA GetDiskFreeSpaceExA GetDiskFreeSpaceExW
 GetDiskFreeSpaceW GetDllDirectoryA GetDllDirectoryW GetDriveTypeA GetDriveTypeW GetEnvironmentStrings GetEnvironmentStringsA GetEnvironmentStringsW
 GetEnvironmentVariableA GetEnvironmentVariableW GetExitCodeProcess GetExitCodeThread GetExpandedNameA GetExpandedNameW GetFileAttributesA GetFileAttributesExA
 GetFileAttributesExW GetFileAttributesW GetFileInformationByHandle GetFileSize GetFileSizeEx GetFileTime GetFileType GetFirmwareEnvironmentVariableA
 GetFirmwareEnvironmentVariableW GetFullPathNameA GetFullPathNameW GetGeoInfoA GetGeoInfoW GetHandleContext GetHandleInformation GetLargestConsoleWindowSize
 GetLastError GetLinguistLangSize GetLocalTime GetLocaleInfoA GetLocaleInfoW GetLogicalDriveStringsA GetLogicalDriveStringsW GetLogicalDrives GetLongPathNameA
 GetLongPathNameW GetMailslotInfo GetModuleFileNameA GetModuleFileNameW GetModuleHandleA GetModuleHandleExA GetModuleHandleExW GetModuleHandleW
 GetNamedPipeHandleStateA GetNamedPipeHandleStateW GetNamedPipeInfo GetNativeSystemInfo GetNextVDMCommand GetNlsSectionName GetNumaAvailableMemory
 GetNumaAvailableMemoryNode GetNumaHighestNodeNumber GetNumaNodeProcessorMask GetNumaProcessorMap GetNumaProcessorNode GetNumberFormatA GetNumberFormatW
 GetNumberOfConsoleFonts GetNumberOfConsoleInputEvents GetNumberOfConsoleMouseButtons GetOEMCP GetOverlappedResult GetPriorityClass GetPrivateProfileIntA
 GetPrivateProfileIntW GetPrivateProfileSectionA GetPrivateProfileSectionNamesA GetPrivateProfileSectionNamesW GetPrivateProfileSectionW
 GetPrivateProfileStringA GetPrivateProfileStringW GetPrivateProfileStructA GetPrivateProfileStructW GetProcAddress GetProcessAffinityMask GetProcessHandleCount
 GetProcessHeap GetProcessHeaps GetProcessId GetProcessIoCounters GetProcessPriorityBoost GetProcessShutdownParameters GetProcessTimes GetProcessVersion
 GetProcessWorkingSetSize GetProfileIntA GetProfileIntW GetProfileSectionA GetProfileSectionW GetProfileStringA GetProfileStringW GetQueuedCompletionStatus
 GetShortPathNameA GetShortPathNameW GetStartupInfoA GetStartupInfoW GetStdHandle GetStringTypeA GetStringTypeExA GetStringTypeExW GetStringTypeW
 GetSystemDefaultLCID GetSystemDefaultLangID GetSystemDefaultUILanguage GetSystemDirectoryA GetSystemDirectoryW GetSystemInfo GetSystemPowerStatus
 GetSystemRegistryQuota GetSystemTime GetSystemTimeAdjustment GetSystemTimeAsFileTime GetSystemTimes GetSystemWindowsDirectoryA GetSystemWindowsDirectoryW
 GetSystemWow64DirectoryA GetSystemWow64DirectoryW GetTapeParameters GetTapePosition GetTapeStatus GetTempFileNameA GetTempFileNameW GetTempPathA GetTempPathW
 GetThreadContext GetThreadIOPendingFlag GetThreadLocale GetThreadPriority GetThreadPriorityBoost GetThreadSelectorEntry GetThreadTimes GetTickCount
 GetTimeFormatA GetTimeFormatW GetTimeZoneInformation GetUserDefaultLCID GetUserDefaultLangID GetUserDefaultUILanguage GetUserGeoID GetVDMCurrentDirectories
 GetVersion GetVersionExA GetVersionExW GetVolumeInformationA GetVolumeInformationW GetVolumeNameForVolumeMountPointA GetVolumeNameForVolumeMountPointW
 GetVolumePathNameA GetVolumePathNameW GetVolumePathNamesForVolumeNameA GetVolumePathNamesForVolumeNameW GetWindowsDirectoryA GetWindowsDirectoryW GetWriteWatch
 GlobalAddAtomA GlobalAddAtomW GlobalAlloc GlobalCompact GlobalDeleteAtom GlobalFindAtomA GlobalFindAtomW GlobalFix GlobalFlags GlobalFree GlobalGetAtomNameA
 GlobalGetAtomNameW GlobalHandle GlobalLock GlobalMemoryStatus GlobalMemoryStatusEx GlobalReAlloc GlobalSize GlobalUnWire GlobalUnfix GlobalUnlock GlobalWire
 Heap32First Heap32ListFirst Heap32ListNext Heap32Next HeapAlloc HeapCompact HeapCreate HeapCreateTagsW HeapDestroy HeapExtend HeapFree HeapLock
 HeapQueryInformation HeapQueryTagW HeapReAlloc HeapSetInformation HeapSize HeapSummary HeapUnlock HeapUsage HeapValidate HeapWalk InitAtomTable
 InitializeCriticalSection InitializeCriticalSectionAndSpinCount InitializeSListHead InterlockedCompareExchange InterlockedDecrement InterlockedExchange
 InterlockedExchangeAdd InterlockedFlushSList InterlockedIncrement InterlockedPopEntrySList InterlockedPushEntrySList InvalidateConsoleDIBits IsBadCodePtr
 IsBadHugeReadPtr IsBadHugeWritePtr IsBadReadPtr IsBadStringPtrA IsBadStringPtrW IsBadWritePtr IsDBCSLeadByte IsDBCSLeadByteEx IsDebuggerPresent IsProcessInJob
 IsProcessorFeaturePresent IsSystemResumeAutomatic IsValidCodePage IsValidLanguageGroup IsValidLocale IsValidUILanguage IsWow64Process LCMapStringA LCMapStringW
 LZClose LZCloseFile LZCopy LZCreateFileW LZDone LZInit LZOpenFileA LZOpenFileW LZRead LZSeek LZStart LeaveCriticalSection LoadLibraryA LoadLibraryExA
 LoadLibraryExW LoadLibraryW LoadModule LoadResource LocalAlloc LocalCompact LocalFileTimeToFileTime LocalFlags LocalFree LocalHandle LocalLock LocalReAlloc
 LocalShrink LocalSize LocalUnlock LockFile LockFileEx LockResource MapUserPhysicalPages MapUserPhysicalPagesScatter MapViewOfFile MapViewOfFileEx Module32First
 Module32FirstW Module32Next Module32NextW MoveFileA MoveFileExA MoveFileExW MoveFileW MoveFileWithProgressA MoveFileWithProgressW MulDiv MultiByteToWideChar
 NlsConvertIntegerToString NlsGetCacheUpdateCount NlsResetProcessLocale NumaVirtualQueryNode OpenConsoleW OpenDataFile OpenEventA OpenEventW OpenFile
 OpenFileMappingA OpenFileMappingW OpenJobObjectA OpenJobObjectW OpenMutexA OpenMutexW OpenProcess OpenProfileUserMapping OpenSemaphoreA OpenSemaphoreW
 OpenThread OpenWaitableTimerA OpenWaitableTimerW OutputDebugStringA OutputDebugStringW PeekConsoleInputA PeekConsoleInputW PeekNamedPipe
 PostQueuedCompletionStatus PrepareTape PrivCopyFileExW PrivMoveFileIdentityW Process32First Process32FirstW Process32Next Process32NextW ProcessIdToSessionId
 PulseEvent PurgeComm QueryActCtxW QueryDepthSList QueryDosDeviceA QueryDosDeviceW QueryInformationJobObject QueryMemoryResourceNotification
 QueryPerformanceCounter QueryPerformanceFrequency QueryWin31IniFilesMappedToRegistry QueueUserAPC QueueUserWorkItem RaiseException ReadConsoleA
 ReadConsoleInputA ReadConsoleInputExA ReadConsoleInputExW ReadConsoleInputW ReadConsoleOutputA ReadConsoleOutputAttribute ReadConsoleOutputCharacterA
 ReadConsoleOutputCharacterW ReadConsoleOutputW ReadConsoleW ReadDirectoryChangesW ReadFile ReadFileEx ReadFileScatter ReadProcessMemory RegisterConsoleIME
 RegisterConsoleOS2 RegisterConsoleVDM RegisterWaitForInputIdle RegisterWaitForSingleObject RegisterWaitForSingleObjectEx RegisterWowBaseHandlers
 RegisterWowExec ReleaseActCtx ReleaseMutex ReleaseSemaphore RemoveDirectoryA RemoveDirectoryW RemoveLocalAlternateComputerNameA
 RemoveLocalAlternateComputerNameW RemoveVectoredExceptionHandler ReplaceFile ReplaceFileA ReplaceFileW RequestDeviceWakeup RequestWakeupLatency ResetEvent
 ResetWriteWatch RestoreLastError ResumeThread RtlCaptureContext RtlCaptureStackBackTrace RtlFillMemory RtlMoveMemory RtlUnwind RtlZeroMemory
 ScrollConsoleScreenBufferA ScrollConsoleScreenBufferW SearchPathA SearchPathW SetCPGlobal SetCalendarInfoA SetCalendarInfoW SetClientTimeZoneInformation
 SetComPlusPackageInstallStatus SetCommBreak SetCommConfig SetCommMask SetCommState SetCommTimeouts SetComputerNameA SetComputerNameExA SetComputerNameExW
 SetComputerNameW SetConsoleActiveScreenBuffer SetConsoleCP SetConsoleCommandHistoryMode SetConsoleCtrlHandler SetConsoleCursor SetConsoleCursorInfo
 SetConsoleCursorMode SetConsoleCursorPosition SetConsoleDisplayMode SetConsoleFont SetConsoleHardwareState SetConsoleIcon SetConsoleInputExeNameA
 SetConsoleInputExeNameW SetConsoleKeyShortcuts SetConsoleLocalEUDC SetConsoleMaximumWindowSize SetConsoleMenuClose SetConsoleMode SetConsoleNlsMode
 SetConsoleNumberOfCommandsA SetConsoleNumberOfCommandsW SetConsoleOS2OemFormat SetConsoleOutputCP SetConsolePalette SetConsoleScreenBufferSize
 SetConsoleTextAttribute SetConsoleTitleA SetConsoleTitleW SetConsoleWindowInfo SetCriticalSectionSpinCount SetCurrentDirectoryA SetCurrentDirectoryW
 SetDefaultCommConfigA SetDefaultCommConfigW SetDllDirectoryA SetDllDirectoryW SetEndOfFile SetEnvironmentVariableA SetEnvironmentVariableW SetErrorMode
 SetEvent SetFileApisToANSI SetFileApisToOEM SetFileAttributesA SetFileAttributesW SetFilePointer SetFilePointerEx SetFileShortNameA SetFileShortNameW
 SetFileTime SetFileValidData SetFirmwareEnvironmentVariableA SetFirmwareEnvironmentVariableW SetHandleContext SetHandleCount SetHandleInformation
 SetInformationJobObject SetLastConsoleEventActive SetLastError SetLocalPrimaryComputerNameA SetLocalPrimaryComputerNameW SetLocalTime SetLocaleInfoA
 SetLocaleInfoW SetMailslotInfo SetMessageWaitingIndicator SetNamedPipeHandleState SetPriorityClass SetProcessAffinityMask SetProcessPriorityBoost
 SetProcessShutdownParameters SetProcessWorkingSetSize SetStdHandle SetSystemPowerState SetSystemTime SetSystemTimeAdjustment SetTapeParameters SetTapePosition
 SetTermsrvAppInstallMode SetThreadAffinityMask SetThreadContext SetThreadExecutionState SetThreadIdealProcessor SetThreadLocale SetThreadPriority
 SetThreadPriorityBoost SetThreadUILanguage SetTimeZoneInformation SetTimerQueueTimer SetUnhandledExceptionFilter SetUserGeoID SetVDMCurrentDirectories
 SetVolumeLabelA SetVolumeLabelW SetVolumeMountPointA SetVolumeMountPointW SetWaitableTimer SetupComm ShowConsoleCursor SignalObjectAndWait SizeofResource Sleep
 SleepEx SuspendThread SwitchToFiber SwitchToThread SystemTimeToFileTime SystemTimeToTzSpecificLocalTime TerminateJobObject TerminateProcess TerminateThread
 TermsrvAppInstallMode Thread32First Thread32Next TlsAlloc TlsFree TlsGetValue TlsSetValue Toolhelp32ReadProcessMemory TransactNamedPipe TransmitCommChar
 TrimVirtualBuffer TryEnterCriticalSection TzSpecificLocalTimeToSystemTime UTRegister UTUnRegister UnhandledExceptionFilter UnlockFile UnlockFileEx
 UnmapViewOfFile UnregisterConsoleIME UnregisterWait UnregisterWaitEx UpdateResourceA UpdateResourceW VDMConsoleOperation VDMOperationStarted ValidateLCType
 ValidateLocale VerLanguageNameA VerLanguageNameW VerSetConditionMask VerifyConsoleIoHandle VerifyVersionInfoA VerifyVersionInfoW VirtualAlloc VirtualAllocEx
 VirtualBufferExceptionHandler VirtualFree VirtualFreeEx VirtualLock VirtualProtect VirtualProtectEx VirtualQuery VirtualQueryEx VirtualUnlock
 WTSGetActiveConsoleSessionId WaitCommEvent WaitForDebugEvent WaitForMultipleObjects WaitForMultipleObjectsEx WaitForSingleObject WaitForSingleObjectEx
 WaitNamedPipeA WaitNamedPipeW WideCharToMultiByte WinExec WriteConsoleA WriteConsoleInputA WriteConsoleInputVDMA WriteConsoleInputVDMW WriteConsoleInputW
 WriteConsoleOutputA WriteConsoleOutputAttribute WriteConsoleOutputCharacterA WriteConsoleOutputCharacterW WriteConsoleOutputW WriteConsoleW WriteFile
 WriteFileEx WriteFileGather WritePrivateProfileSectionA WritePrivateProfileSectionW WritePrivateProfileStringA WritePrivateProfileStringW
 WritePrivateProfileStructA WritePrivateProfileStructW WriteProcessMemory WriteProfileSectionA WriteProfileSectionW WriteProfileStringA WriteProfileStringW
 WriteTapemark ZombifyActCtx _hread _hwrite _lclose _lcreat _llseek _lopen _lread _lwrite lstrcat lstrcatA lstrcatW lstrcmp lstrcmpA lstrcmpW lstrcmpi lstrcmpiA
 lstrcmpiW lstrcpy lstrcpyA lstrcpyW lstrcpyn lstrcpynA lstrcpynW lstrlen lstrlenA lstrlenW
ntdll
 PropertyLengthAsVariant RtlConvertPropertyToVariant RtlConvertVariantToProperty RtlInterlockedPushListSList RtlUlongByteSwap RtlUlonglongByteSwap
 RtlUshortByteSwap CsrAllocateCaptureBuffer CsrAllocateMessagePointer CsrCaptureMessageBuffer CsrCaptureMessageMultiUnicodeStringsInPlace
 CsrCaptureMessageString CsrCaptureTimeout CsrClientCallServer CsrClientConnectToServer CsrFreeCaptureBuffer CsrGetProcessId CsrIdentifyAlertableThread
 CsrNewThread CsrProbeForRead CsrProbeForWrite CsrSetPriorityClass DbgBreakPoint DbgPrint DbgPrintEx DbgPrintReturnControlC DbgPrompt DbgQueryDebugFilterState
 DbgSetDebugFilterState DbgUiConnectToDbg DbgUiContinue DbgUiConvertStateChangeStructure DbgUiDebugActiveProcess DbgUiGetThreadDebugObject
 DbgUiIssueRemoteBreakin DbgUiRemoteBreakin DbgUiSetThreadDebugObject DbgUiStopDebugging DbgUiWaitStateChange DbgUserBreakPoint KiFastSystemCall
 KiFastSystemCallRet KiIntSystemCall KiRaiseUserExceptionDispatcher KiUserApcDispatcher KiUserCallbackDispatcher KiUserExceptionDispatcher
 LdrAccessOutOfProcessResource LdrAccessResource LdrAddRefDll LdrAlternateResourcesEnabled LdrCreateOutOfProcessImage LdrDestroyOutOfProcessImage
 LdrDisableThreadCalloutsForDll LdrEnumResources LdrEnumerateLoadedModules LdrFindCreateProcessManifest LdrFindEntryForAddress LdrFindResourceDirectory_U
 LdrFindResourceEx_U LdrFindResource_U LdrFlushAlternateResourceModules LdrGetDllHandle LdrGetDllHandleEx LdrGetProcedureAddress LdrHotPatchRoutine
 LdrInitShimEngineDynamic LdrInitializeThunk LdrLoadAlternateResourceModule LdrLoadDll LdrLockLoaderLock LdrProcessRelocationBlock
 LdrQueryImageFileExecutionOptions LdrQueryProcessModuleInformation LdrSetAppCompatDllRedirectionCallback LdrSetDllManifestProber LdrShutdownProcess
 LdrShutdownThread LdrUnloadAlternateResourceModule LdrUnloadDll LdrUnlockLoaderLock LdrVerifyImageMatchesChecksum NlsAnsiCodePage NlsMbCodePageTag
 NlsMbOemCodePageTag NtAcceptConnectPort NtAccessCheck NtAccessCheckAndAuditAlarm NtAccessCheckByType NtAccessCheckByTypeAndAuditAlarm
 NtAccessCheckByTypeResultList NtAccessCheckByTypeResultListAndAuditAlarm NtAccessCheckByTypeResultListAndAuditAlarmByHandle NtAddAtom NtAddBootEntry
 NtAdjustGroupsToken NtAdjustPrivilegesToken NtAlertResumeThread NtAlertThread NtAllocateLocallyUniqueId NtAllocateUserPhysicalPages NtAllocateUuids
 NtAllocateVirtualMemory NtAreMappedFilesTheSame NtAssignProcessToJobObject NtCallbackReturn NtCancelDeviceWakeupRequest NtCancelIoFile NtCancelTimer
 NtClearEvent NtClose NtCloseObjectAuditAlarm NtCompactKeys NtCompareTokens NtCompleteConnectPort NtCompressKey NtConnectPort NtContinue NtCreateDebugObject
 NtCreateDirectoryObject NtCreateEvent NtCreateEventPair NtCreateFile NtCreateIoCompletion NtCreateJobObject NtCreateJobSet NtCreateKey NtCreateKeyedEvent
 NtCreateMailslotFile NtCreateMutant NtCreateNamedPipeFile NtCreatePagingFile NtCreatePort NtCreateProcess NtCreateProcessEx NtCreateProfile NtCreateSection
 NtCreateSemaphore NtCreateSymbolicLinkObject NtCreateThread NtCreateTimer NtCreateToken NtCreateWaitablePort NtCurrentTeb NtDebugActiveProcess NtDebugContinue
 NtDelayExecution NtDeleteAtom NtDeleteBootEntry NtDeleteFile NtDeleteKey NtDeleteObjectAuditAlarm NtDeleteValueKey NtDeviceIoControlFile NtDisplayString
 NtDuplicateObject NtDuplicateToken NtEnumerateBootEntries NtEnumerateKey NtEnumerateSystemEnvironmentValuesEx NtEnumerateValueKey NtExtendSection NtFilterToken
 NtFindAtom NtFlushBuffersFile NtFlushInstructionCache NtFlushKey NtFlushVirtualMemory NtFlushWriteBuffer NtFreeUserPhysicalPages NtFreeVirtualMemory
 NtFsControlFile NtGetContextThread NtGetDevicePowerState NtGetPlugPlayEvent NtGetWriteWatch NtImpersonateAnonymousToken NtImpersonateClientOfPort
 NtImpersonateThread NtInitializeRegistry NtInitiatePowerAction NtIsProcessInJob NtIsSystemResumeAutomatic NtListenPort NtLoadDriver NtLoadKey2 NtLoadKey
 NtLockFile NtLockProductActivationKeys NtLockRegistryKey NtLockVirtualMemory NtMakePermanentObject NtMakeTemporaryObject NtMapUserPhysicalPages
 NtMapUserPhysicalPagesScatter NtMapViewOfSection NtModifyBootEntry NtNotifyChangeDirectoryFile NtNotifyChangeKey NtNotifyChangeMultipleKeys
 NtOpenDirectoryObject NtOpenEvent NtOpenEventPair NtOpenFile NtOpenIoCompletion NtOpenJobObject NtOpenKey NtOpenKeyedEvent NtOpenMutant NtOpenObjectAuditAlarm
 NtOpenProcess NtOpenProcessToken NtOpenProcessTokenEx NtOpenSection NtOpenSemaphore NtOpenSymbolicLinkObject NtOpenThread NtOpenThreadToken NtOpenThreadTokenEx
 NtOpenTimer NtPlugPlayControl NtPowerInformation NtPrivilegeCheck NtPrivilegeObjectAuditAlarm NtPrivilegedServiceAuditAlarm NtProtectVirtualMemory NtPulseEvent
 NtQueryAttributesFile NtQueryBootEntryOrder NtQueryBootOptions NtQueryDebugFilterState NtQueryDefaultLocale NtQueryDefaultUILanguage NtQueryDirectoryFile
 NtQueryDirectoryObject NtQueryEaFile NtQueryEvent NtQueryFullAttributesFile NtQueryInformationAtom NtQueryInformationFile NtQueryInformationJobObject
 NtQueryInformationPort NtQueryInformationProcess NtQueryInformationThread NtQueryInformationToken NtQueryInstallUILanguage NtQueryIntervalProfile
 NtQueryIoCompletion NtQueryKey NtQueryMultipleValueKey NtQueryMutant NtQueryObject NtQueryOpenSubKeys NtQueryPerformanceCounter NtQueryPortInformationProcess
 NtQueryQuotaInformationFile NtQuerySection NtQuerySecurityObject NtQuerySemaphore NtQuerySymbolicLinkObject NtQuerySystemEnvironmentValue
 NtQuerySystemEnvironmentValueEx NtQuerySystemInformation NtQuerySystemTime NtQueryTimer NtQueryTimerResolution NtQueryValueKey NtQueryVirtualMemory
 NtQueryVolumeInformationFile NtQueueApcThread NtRaiseException NtRaiseHardError NtReadFile NtReadFileScatter NtReadRequestData NtReadVirtualMemory
 NtRegisterThreadTerminatePort NtReleaseKeyedEvent NtReleaseMutant NtReleaseSemaphore NtRemoveIoCompletion NtRemoveProcessDebug NtRenameKey NtReplaceKey
 NtReplyPort NtReplyWaitReceivePort NtReplyWaitReceivePortEx NtReplyWaitReplyPort NtRequestDeviceWakeup NtRequestPort NtRequestWaitReplyPort
 NtRequestWakeupLatency NtResetEvent NtResetWriteWatch NtRestoreKey NtResumeProcess NtResumeThread NtSaveKey NtSaveKeyEx NtSaveMergedKeys NtSecureConnectPort
 NtSetBootEntryOrder NtSetBootOptions NtSetContextThread NtSetDebugFilterState NtSetDefaultHardErrorPort NtSetDefaultLocale NtSetDefaultUILanguage NtSetEaFile
 NtSetEvent NtSetEventBoostPriority NtSetHighEventPair NtSetHighWaitLowEventPair NtSetInformationDebugObject NtSetInformationFile NtSetInformationJobObject
 NtSetInformationKey NtSetInformationObject NtSetInformationProcess NtSetInformationThread NtSetInformationToken NtSetIntervalProfile NtSetIoCompletion
 NtSetLdtEntries NtSetLowEventPair NtSetLowWaitHighEventPair NtSetQuotaInformationFile NtSetSecurityObject NtSetSystemEnvironmentValue
 NtSetSystemEnvironmentValueEx NtSetSystemInformation NtSetSystemPowerState NtSetSystemTime NtSetThreadExecutionState NtSetTimer NtSetTimerResolution
 NtSetUuidSeed NtSetValueKey NtSetVolumeInformationFile NtShutdownSystem NtSignalAndWaitForSingleObject NtStartProfile NtStopProfile NtSuspendProcess
 NtSuspendThread NtSystemDebugControl NtTerminateJobObject NtTerminateProcess NtTerminateThread NtTestAlert NtTraceEvent NtTranslateFilePath NtUnloadDriver
 NtUnloadKey NtUnloadKeyEx NtUnlockFile NtUnlockVirtualMemory NtUnmapViewOfSection NtVdmControl NtWaitForDebugEvent NtWaitForKeyedEvent NtWaitForMultipleObjects
 NtWaitForSingleObject NtWaitHighEventPair NtWaitLowEventPair NtWriteFile NtWriteFileGather NtWriteRequestData NtWriteVirtualMemory NtYieldExecution
 PfxFindPrefix PfxInitialize PfxInsertPrefix PfxRemovePrefix RtlAbortRXact RtlAbsoluteToSelfRelativeSD RtlAcquirePebLock RtlAcquireResourceExclusive
 RtlAcquireResourceShared RtlActivateActivationContext RtlActivateActivationContextEx RtlActivateActivationContextUnsafeFast RtlAddAccessAllowedAce
 RtlAddAccessAllowedAceEx RtlAddAccessAllowedObjectAce RtlAddAccessDeniedAce RtlAddAccessDeniedAceEx RtlAddAccessDeniedObjectAce RtlAddAce RtlAddActionToRXact
 RtlAddAtomToAtomTable RtlAddAttributeActionToRXact RtlAddAuditAccessAce RtlAddAuditAccessAceEx RtlAddAuditAccessObjectAce RtlAddCompoundAce RtlAddRange
 RtlAddRefActivationContext RtlAddRefMemoryStream RtlAddVectoredExceptionHandler RtlAddressInSectionTable RtlAdjustPrivilege RtlAllocateAndInitializeSid
 RtlAllocateHandle RtlAllocateHeap RtlAnsiCharToUnicodeChar RtlAnsiStringToUnicodeSize RtlAnsiStringToUnicodeString RtlAppendAsciizToString RtlAppendPathElement
 RtlAppendStringToString RtlAppendUnicodeStringToString RtlAppendUnicodeToString RtlApplicationVerifierStop RtlApplyRXact RtlApplyRXactNoFlush
 RtlAreAllAccessesGranted RtlAreAnyAccessesGranted RtlAreBitsClear RtlAreBitsSet RtlAssert2 RtlAssert RtlCancelTimer RtlCaptureContext RtlCaptureStackBackTrace
 RtlCaptureStackContext RtlCharToInteger RtlCheckForOrphanedCriticalSections RtlCheckProcessParameters RtlCheckRegistryKey RtlClearAllBits RtlClearBits
 RtlCloneMemoryStream RtlCommitMemoryStream RtlCompactHeap RtlCompareMemory RtlCompareMemoryUlong RtlCompareString RtlCompareUnicodeString RtlCompressBuffer
 RtlComputeCrc32 RtlComputeImportTableHash RtlComputePrivatizedDllName_U RtlConsoleMultiByteToUnicodeN RtlConvertExclusiveToShared RtlConvertLongToLargeInteger
 RtlConvertSharedToExclusive RtlConvertSidToUnicodeString RtlConvertToAutoInheritSecurityObject RtlConvertUiListToApiList RtlConvertUlongToLargeInteger
 RtlCopyLuid RtlCopyLuidAndAttributesArray RtlCopyMemoryStreamTo RtlCopyOutOfProcessMemoryStreamTo RtlCopyRangeList RtlCopySecurityDescriptor RtlCopySid
 RtlCopySidAndAttributesArray RtlCopyString RtlCopyUnicodeString RtlCreateAcl RtlCreateActivationContext RtlCreateAndSetSD RtlCreateAtomTable
 RtlCreateBootStatusDataFile RtlCreateEnvironment RtlCreateHeap RtlCreateProcessParameters RtlCreateQueryDebugBuffer RtlCreateRegistryKey
 RtlCreateSecurityDescriptor RtlCreateSystemVolumeInformationFolder RtlCreateTagHeap RtlCreateTimer RtlCreateTimerQueue RtlCreateUnicodeString
 RtlCreateUnicodeStringFromAsciiz RtlCreateUserProcess RtlCreateUserSecurityObject RtlCreateUserThread RtlCustomCPToUnicodeN RtlCutoverTimeToSystemTime
 RtlDeNormalizeProcessParams RtlDeactivateActivationContext RtlDeactivateActivationContextUnsafeFast RtlDebugPrintTimes RtlDecodePointer RtlDecodeSystemPointer
 RtlDecompressBuffer RtlDecompressFragment RtlDefaultNpAcl RtlDelete RtlDeleteAce RtlDeleteAtomFromAtomTable RtlDeleteCriticalSection
 RtlDeleteElementGenericTable RtlDeleteElementGenericTableAvl RtlDeleteNoSplay RtlDeleteOwnersRanges RtlDeleteRange RtlDeleteRegistryValue RtlDeleteResource
 RtlDeleteSecurityObject RtlDeleteTimer RtlDeleteTimerQueue RtlDeleteTimerQueueEx RtlDeregisterWait RtlDeregisterWaitEx RtlDestroyAtomTable
 RtlDestroyEnvironment RtlDestroyHandleTable RtlDestroyHeap RtlDestroyProcessParameters RtlDestroyQueryDebugBuffer RtlDetermineDosPathNameType_U
 RtlDllShutdownInProgress RtlDnsHostNameToComputerName RtlDoesFileExists_U RtlDosApplyFileIsolationRedirection_Ustr RtlDosPathNameToNtPathName_U
 RtlDosSearchPath_U RtlDosSearchPath_Ustr RtlDowncaseUnicodeChar RtlDowncaseUnicodeString RtlDumpResource RtlDuplicateUnicodeString RtlEmptyAtomTable
 RtlEnableEarlyCriticalSectionEventCreation RtlEncodePointer RtlEncodeSystemPointer RtlEnlargedIntegerMultiply RtlEnlargedUnsignedDivide
 RtlEnlargedUnsignedMultiply RtlEnterCriticalSection RtlEnumProcessHeaps RtlEnumerateGenericTable RtlEnumerateGenericTableAvl
 RtlEnumerateGenericTableLikeADirectory RtlEnumerateGenericTableWithoutSplaying RtlEnumerateGenericTableWithoutSplayingAvl RtlEqualComputerName
 RtlEqualDomainName RtlEqualLuid RtlEqualPrefixSid RtlEqualSid RtlEqualString RtlEqualUnicodeString RtlEraseUnicodeString RtlExitUserThread
 RtlExpandEnvironmentStrings_U RtlExtendHeap RtlExtendedIntegerMultiply RtlExtendedLargeIntegerDivide RtlExtendedMagicDivide RtlFillMemory RtlFillMemoryUlong
 RtlFinalReleaseOutOfProcessMemoryStream RtlFindActivationContextSectionGuid RtlFindActivationContextSectionString RtlFindCharInUnicodeString RtlFindClearBits
 RtlFindClearBitsAndSet RtlFindClearRuns RtlFindLastBackwardRunClear RtlFindLeastSignificantBit RtlFindLongestRunClear RtlFindMessage RtlFindMostSignificantBit
 RtlFindNextForwardRunClear RtlFindRange RtlFindSetBits RtlFindSetBitsAndClear RtlFirstEntrySList RtlFirstFreeAce RtlFlushSecureMemoryCache
 RtlFormatCurrentUserKeyPath RtlFormatMessage RtlFreeAnsiString RtlFreeHandle RtlFreeHeap RtlFreeOemString RtlFreeRangeList RtlFreeSid
 RtlFreeThreadActivationContextStack RtlFreeUnicodeString RtlFreeUserThreadStack RtlGUIDFromString RtlGenerate8dot3Name RtlGetAce RtlGetActiveActivationContext
 RtlGetCallersAddress RtlGetCompressionWorkSpaceSize RtlGetControlSecurityDescriptor RtlGetCurrentDirectory_U RtlGetCurrentPeb RtlGetDaclSecurityDescriptor
 RtlGetElementGenericTable RtlGetElementGenericTableAvl RtlGetFirstRange RtlGetFrame RtlGetFullPathName_U RtlGetGroupSecurityDescriptor RtlGetLastNtStatus
 RtlGetLastWin32Error RtlGetLengthWithoutLastFullDosOrNtPathElement RtlGetLengthWithoutTrailingPathSeperators RtlGetLongestNtPathLength
 RtlGetNativeSystemInformation RtlGetNextRange RtlGetNtGlobalFlags RtlGetNtProductType RtlGetNtVersionNumbers RtlGetOwnerSecurityDescriptor RtlGetProcessHeaps
 RtlGetSaclSecurityDescriptor RtlGetSecurityDescriptorRMControl RtlGetSetBootStatusData RtlGetUnloadEventTrace RtlGetUserInfoHeap RtlGetVersion
 RtlHashUnicodeString RtlIdentifierAuthoritySid RtlImageDirectoryEntryToData RtlImageNtHeader RtlImageRvaToSection RtlImageRvaToVa RtlImpersonateSelf
 RtlInitAnsiString RtlInitCodePageTable RtlInitMemoryStream RtlInitNlsTables RtlInitOutOfProcessMemoryStream RtlInitString RtlInitUnicodeString
 RtlInitUnicodeStringEx RtlInitializeAtomPackage RtlInitializeBitMap RtlInitializeContext RtlInitializeCriticalSection RtlInitializeCriticalSectionAndSpinCount
 RtlInitializeGenericTable RtlInitializeGenericTableAvl RtlInitializeHandleTable RtlInitializeRXact RtlInitializeRangeList RtlInitializeResource
 RtlInitializeSListHead RtlInitializeSid RtlInitializeStackTraceDataBase RtlInsertElementGenericTable RtlInsertElementGenericTableAvl RtlInt64ToUnicodeString
 RtlIntegerToChar RtlIntegerToUnicodeString RtlInterlockedFlushSList RtlInterlockedPopEntrySList RtlInterlockedPushEntrySList RtlInvertRangeList
 RtlIpv4AddressToStringA RtlIpv4AddressToStringExA RtlIpv4AddressToStringExW RtlIpv4AddressToStringW RtlIpv4StringToAddressA RtlIpv4StringToAddressExA
 RtlIpv4StringToAddressExW RtlIpv4StringToAddressW RtlIpv6AddressToStringA RtlIpv6AddressToStringExA RtlIpv6AddressToStringExW RtlIpv6AddressToStringW
 RtlIpv6StringToAddressA RtlIpv6StringToAddressExA RtlIpv6StringToAddressExW RtlIpv6StringToAddressW RtlIsActivationContextActive RtlIsDosDeviceName_U
 RtlIsGenericTableEmpty RtlIsGenericTableEmptyAvl RtlIsNameLegalDOS8Dot3 RtlIsRangeAvailable RtlIsTextUnicode RtlIsThreadWithinLoaderCallout RtlIsValidHandle
 RtlIsValidIndexHandle RtlLargeIntegerAdd RtlLargeIntegerArithmeticShift RtlLargeIntegerDivide RtlLargeIntegerNegate RtlLargeIntegerShiftLeft
 RtlLargeIntegerShiftRight RtlLargeIntegerSubtract RtlLargeIntegerToChar RtlLeaveCriticalSection RtlLengthRequiredSid RtlLengthSecurityDescriptor RtlLengthSid
 RtlLocalTimeToSystemTime RtlLockBootStatusData RtlLockHeap RtlLockMemoryStreamRegion RtlLogStackBackTrace RtlLookupAtomInAtomTable RtlLookupElementGenericTable
 RtlLookupElementGenericTableAvl RtlMakeSelfRelativeSD RtlMapGenericMask RtlMapSecurityErrorToNtStatus RtlMergeRangeLists RtlMoveMemory
 RtlMultiAppendUnicodeStringBuffer RtlMultiByteToUnicodeN RtlMultiByteToUnicodeSize RtlNewInstanceSecurityObject RtlNewSecurityGrantedAccess
 RtlNewSecurityObject RtlNewSecurityObjectEx RtlNewSecurityObjectWithMultipleInheritance RtlNormalizeProcessParams RtlNtPathNameToDosPathName
 RtlNtStatusToDosError RtlNtStatusToDosErrorNoTeb RtlNumberGenericTableElements RtlNumberGenericTableElementsAvl RtlNumberOfClearBits RtlNumberOfSetBits
 RtlOemStringToUnicodeSize RtlOemStringToUnicodeString RtlOemToUnicodeN RtlOpenCurrentUser RtlPcToFileHeader RtlPinAtomInAtomTable RtlPopFrame RtlPrefixString
 RtlPrefixUnicodeString RtlProtectHeap RtlPushFrame RtlQueryAtomInAtomTable RtlQueryDepthSList RtlQueryEnvironmentVariable_U RtlQueryHeapInformation
 RtlQueryInformationAcl RtlQueryInformationActivationContext RtlQueryInformationActiveActivationContext RtlQueryInterfaceMemoryStream
 RtlQueryProcessBackTraceInformation RtlQueryProcessDebugInformation RtlQueryProcessHeapInformation RtlQueryProcessLockInformation RtlQueryRegistryValues
 RtlQuerySecurityObject RtlQueryTagHeap RtlQueryTimeZoneInformation RtlQueueApcWow64Thread RtlQueueWorkItem RtlRaiseException RtlRaiseStatus RtlRandom
 RtlRandomEx RtlReAllocateHeap RtlReadMemoryStream RtlReadOutOfProcessMemoryStream RtlRealPredecessor RtlRealSuccessor RtlRegisterSecureMemoryCacheCallback
 RtlRegisterWait RtlReleaseActivationContext RtlReleaseMemoryStream RtlReleasePebLock RtlReleaseResource RtlRemoteCall RtlRemoveVectoredExceptionHandler
 RtlResetRtlTranslations RtlRestoreLastWin32Error RtlRevertMemoryStream RtlRunDecodeUnicodeString RtlRunEncodeUnicodeString RtlSecondsSince1970ToTime
 RtlSecondsSince1980ToTime RtlSeekMemoryStream RtlSelfRelativeToAbsoluteSD2 RtlSelfRelativeToAbsoluteSD RtlSetAllBits RtlSetAttributesSecurityDescriptor
 RtlSetBits RtlSetControlSecurityDescriptor RtlSetCriticalSectionSpinCount RtlSetCurrentDirectory_U RtlSetCurrentEnvironment RtlSetDaclSecurityDescriptor
 RtlSetEnvironmentVariable RtlSetGroupSecurityDescriptor RtlSetHeapInformation RtlSetInformationAcl RtlSetIoCompletionCallback RtlSetLastWin32Error
 RtlSetLastWin32ErrorAndNtStatusFromNtStatus RtlSetMemoryStreamSize RtlSetOwnerSecurityDescriptor RtlSetProcessIsCritical RtlSetSaclSecurityDescriptor
 RtlSetSecurityDescriptorRMControl RtlSetSecurityObject RtlSetSecurityObjectEx RtlSetThreadIsCritical RtlSetThreadPoolStartFunc RtlSetTimeZoneInformation
 RtlSetTimer RtlSetUnicodeCallouts RtlSetUserFlagsHeap RtlSetUserValueHeap RtlSizeHeap RtlSplay RtlStartRXact RtlStatMemoryStream RtlStringFromGUID
 RtlSubAuthorityCountSid RtlSubAuthoritySid RtlSubtreePredecessor RtlSubtreeSuccessor RtlSystemTimeToLocalTime RtlTimeFieldsToTime RtlTimeToElapsedTimeFields
 RtlTimeToSecondsSince1970 RtlTimeToSecondsSince1980 RtlTimeToTimeFields RtlTraceDatabaseAdd RtlTraceDatabaseCreate RtlTraceDatabaseDestroy
 RtlTraceDatabaseEnumerate RtlTraceDatabaseFind RtlTraceDatabaseLock RtlTraceDatabaseUnlock RtlTraceDatabaseValidate RtlTryEnterCriticalSection
 RtlUnhandledExceptionFilter2 RtlUnhandledExceptionFilter RtlUnicodeStringToAnsiSize RtlUnicodeStringToAnsiString RtlUnicodeStringToCountedOemString
 RtlUnicodeStringToInteger RtlUnicodeStringToOemSize RtlUnicodeStringToOemString RtlUnicodeToCustomCPN RtlUnicodeToMultiByteN RtlUnicodeToMultiByteSize
 RtlUnicodeToOemN RtlUniform RtlUnlockBootStatusData RtlUnlockHeap RtlUnlockMemoryStreamRegion RtlUnwind RtlUpcaseUnicodeChar RtlUpcaseUnicodeString
 RtlUpcaseUnicodeStringToAnsiString RtlUpcaseUnicodeStringToCountedOemString RtlUpcaseUnicodeStringToOemString RtlUpcaseUnicodeToCustomCPN
 RtlUpcaseUnicodeToMultiByteN RtlUpcaseUnicodeToOemN RtlUpdateTimer RtlUpperChar RtlUpperString RtlUsageHeap RtlValidAcl RtlValidRelativeSecurityDescriptor
 RtlValidSecurityDescriptor RtlValidSid RtlValidateHeap RtlValidateProcessHeaps RtlValidateUnicodeString RtlVerifyVersionInfo RtlWalkFrameChain RtlWalkHeap
 RtlWriteMemoryStream RtlWriteRegistryValue RtlZeroHeap RtlZeroMemory RtlZombifyActivationContext RtlpApplyLengthFunction RtlpEnsureBufferSize
 RtlpNotOwnerCriticalSection RtlpNtCreateKey RtlpNtEnumerateSubKey RtlpNtMakeTemporaryKey RtlpNtOpenKey RtlpNtQueryValueKey RtlpNtSetValueKey
 RtlpUnWaitCriticalSection RtlpWaitForCriticalSection RtlxAnsiStringToUnicodeSize RtlxOemStringToUnicodeSize RtlxUnicodeStringToAnsiSize
 RtlxUnicodeStringToOemSize VerSetConditionMask ZwAcceptConnectPort ZwAccessCheck ZwAccessCheckAndAuditAlarm ZwAccessCheckByType
 ZwAccessCheckByTypeAndAuditAlarm ZwAccessCheckByTypeResultList ZwAccessCheckByTypeResultListAndAuditAlarm ZwAccessCheckByTypeResultListAndAuditAlarmByHandle
 ZwAddAtom ZwAddBootEntry ZwAdjustGroupsToken ZwAdjustPrivilegesToken ZwAlertResumeThread ZwAlertThread ZwAllocateLocallyUniqueId ZwAllocateUserPhysicalPages
 ZwAllocateUuids ZwAllocateVirtualMemory ZwAreMappedFilesTheSame ZwAssignProcessToJobObject ZwCallbackReturn ZwCancelDeviceWakeupRequest ZwCancelIoFile
 ZwCancelTimer ZwClearEvent ZwClose ZwCloseObjectAuditAlarm ZwCompactKeys ZwCompareTokens ZwCompleteConnectPort ZwCompressKey ZwConnectPort ZwContinue
 ZwCreateDebugObject ZwCreateDirectoryObject ZwCreateEvent ZwCreateEventPair ZwCreateFile ZwCreateIoCompletion ZwCreateJobObject ZwCreateJobSet ZwCreateKey
 ZwCreateKeyedEvent ZwCreateMailslotFile ZwCreateMutant ZwCreateNamedPipeFile ZwCreatePagingFile ZwCreatePort ZwCreateProcess ZwCreateProcessEx ZwCreateProfile
 ZwCreateSection ZwCreateSemaphore ZwCreateSymbolicLinkObject ZwCreateThread ZwCreateTimer ZwCreateToken ZwCreateWaitablePort ZwDebugActiveProcess
 ZwDebugContinue ZwDelayExecution ZwDeleteAtom ZwDeleteBootEntry ZwDeleteFile ZwDeleteKey ZwDeleteObjectAuditAlarm ZwDeleteValueKey ZwDeviceIoControlFile
 ZwDisplayString ZwDuplicateObject ZwDuplicateToken ZwEnumerateBootEntries ZwEnumerateKey ZwEnumerateSystemEnvironmentValuesEx ZwEnumerateValueKey
 ZwExtendSection ZwFilterToken ZwFindAtom ZwFlushBuffersFile ZwFlushInstructionCache ZwFlushKey ZwFlushVirtualMemory ZwFlushWriteBuffer ZwFreeUserPhysicalPages
 ZwFreeVirtualMemory ZwFsControlFile ZwGetContextThread ZwGetDevicePowerState ZwGetPlugPlayEvent ZwGetWriteWatch ZwImpersonateAnonymousToken
 ZwImpersonateClientOfPort ZwImpersonateThread ZwInitializeRegistry ZwInitiatePowerAction ZwIsProcessInJob ZwIsSystemResumeAutomatic ZwListenPort ZwLoadDriver
 ZwLoadKey2 ZwLoadKey ZwLockFile ZwLockProductActivationKeys ZwLockRegistryKey ZwLockVirtualMemory ZwMakePermanentObject ZwMakeTemporaryObject
 ZwMapUserPhysicalPages ZwMapUserPhysicalPagesScatter ZwMapViewOfSection ZwModifyBootEntry ZwNotifyChangeDirectoryFile ZwNotifyChangeKey
 ZwNotifyChangeMultipleKeys ZwOpenDirectoryObject ZwOpenEvent ZwOpenEventPair ZwOpenFile ZwOpenIoCompletion ZwOpenJobObject ZwOpenKey ZwOpenKeyedEvent
 ZwOpenMutant ZwOpenObjectAuditAlarm ZwOpenProcess ZwOpenProcessToken ZwOpenProcessTokenEx ZwOpenSection ZwOpenSemaphore ZwOpenSymbolicLinkObject ZwOpenThread
 ZwOpenThreadToken ZwOpenThreadTokenEx ZwOpenTimer ZwPlugPlayControl ZwPowerInformation ZwPrivilegeCheck ZwPrivilegeObjectAuditAlarm
 ZwPrivilegedServiceAuditAlarm ZwProtectVirtualMemory ZwPulseEvent ZwQueryAttributesFile ZwQueryBootEntryOrder ZwQueryBootOptions ZwQueryDebugFilterState
 ZwQueryDefaultLocale ZwQueryDefaultUILanguage ZwQueryDirectoryFile ZwQueryDirectoryObject ZwQueryEaFile ZwQueryEvent ZwQueryFullAttributesFile
 ZwQueryInformationAtom ZwQueryInformationFile ZwQueryInformationJobObject ZwQueryInformationPort ZwQueryInformationProcess ZwQueryInformationThread
 ZwQueryInformationToken ZwQueryInstallUILanguage ZwQueryIntervalProfile ZwQueryIoCompletion ZwQueryKey ZwQueryMultipleValueKey ZwQueryMutant ZwQueryObject
 ZwQueryOpenSubKeys ZwQueryPerformanceCounter ZwQueryPortInformationProcess ZwQueryQuotaInformationFile ZwQuerySection ZwQuerySecurityObject ZwQuerySemaphore
 ZwQuerySymbolicLinkObject ZwQuerySystemEnvironmentValue ZwQuerySystemEnvironmentValueEx ZwQuerySystemInformation ZwQuerySystemTime ZwQueryTimer
 ZwQueryTimerResolution ZwQueryValueKey ZwQueryVirtualMemory ZwQueryVolumeInformationFile ZwQueueApcThread ZwRaiseException ZwRaiseHardError ZwReadFile
 ZwReadFileScatter ZwReadRequestData ZwReadVirtualMemory ZwRegisterThreadTerminatePort ZwReleaseKeyedEvent ZwReleaseMutant ZwReleaseSemaphore
 ZwRemoveIoCompletion ZwRemoveProcessDebug ZwRenameKey ZwReplaceKey ZwReplyPort ZwReplyWaitReceivePort ZwReplyWaitReceivePortEx ZwReplyWaitReplyPort
 ZwRequestDeviceWakeup ZwRequestPort ZwRequestWaitReplyPort ZwRequestWakeupLatency ZwResetEvent ZwResetWriteWatch ZwRestoreKey ZwResumeProcess ZwResumeThread
 ZwSaveKey ZwSaveKeyEx ZwSaveMergedKeys ZwSecureConnectPort ZwSetBootEntryOrder ZwSetBootOptions ZwSetContextThread ZwSetDebugFilterState
 ZwSetDefaultHardErrorPort ZwSetDefaultLocale ZwSetDefaultUILanguage ZwSetEaFile ZwSetEvent ZwSetEventBoostPriority ZwSetHighEventPair ZwSetHighWaitLowEventPair
 ZwSetInformationDebugObject ZwSetInformationFile ZwSetInformationJobObject ZwSetInformationKey ZwSetInformationObject ZwSetInformationProcess
 ZwSetInformationThread ZwSetInformationToken ZwSetIntervalProfile ZwSetIoCompletion ZwSetLdtEntries ZwSetLowEventPair ZwSetLowWaitHighEventPair
 ZwSetQuotaInformationFile ZwSetSecurityObject ZwSetSystemEnvironmentValue ZwSetSystemEnvironmentValueEx ZwSetSystemInformation ZwSetSystemPowerState
 ZwSetSystemTime ZwSetThreadExecutionState ZwSetTimer ZwSetTimerResolution ZwSetUuidSeed ZwSetValueKey ZwSetVolumeInformationFile ZwShutdownSystem
 ZwSignalAndWaitForSingleObject ZwStartProfile ZwStopProfile ZwSuspendProcess ZwSuspendThread ZwSystemDebugControl ZwTerminateJobObject ZwTerminateProcess
 ZwTerminateThread ZwTestAlert ZwTraceEvent ZwTranslateFilePath ZwUnloadDriver ZwUnloadKey ZwUnloadKeyEx ZwUnlockFile ZwUnlockVirtualMemory ZwUnmapViewOfSection
 ZwVdmControl ZwWaitForDebugEvent ZwWaitForKeyedEvent ZwWaitForMultipleObjects ZwWaitForSingleObject ZwWaitHighEventPair ZwWaitLowEventPair ZwWriteFile
 ZwWriteFileGather ZwWriteRequestData ZwWriteVirtualMemory ZwYieldExecution _CIcos _CIlog _CIpow _CIsin _CIsqrt __isascii __iscsym __iscsymf __toascii _alldiv
 _alldvrm _allmul _alloca_probe _allrem _allshl _allshr _atoi64 _aulldiv _aulldvrm _aullrem _aullshr _chkstk _fltused _ftol _i64toa _i64tow _itoa _itow _lfind
 _ltoa _ltow _memccpy _memicmp _snprintf _snwprintf _splitpath _strcmpi _stricmp _strlwr _strnicmp _strupr _tolower _toupper _ui64toa _ui64tow _ultoa _ultow
 _vsnprintf _vsnwprintf _wcsicmp _wcslwr _wcsnicmp _wcsupr _wtoi _wtoi64 _wtol abs atan atoi atol bsearch ceil cos fabs floor isalnum isalpha iscntrl isdigit
 isgraph islower isprint ispunct isspace isupper iswalpha iswctype iswdigit iswlower iswspace iswxdigit isxdigit labs log mbstowcs memchr memcmp memcpy memmove
 memset pow qsort sin sprintf sqrt sscanf strcat strchr strcmp strcpy strcspn strlen strncat strncmp strncpy strpbrk strrchr strspn strstr strtol strtoul
 swprintf tan tolower toupper towlower towupper vDbgPrintEx vDbgPrintExWithPrefix vsprintf wcscat wcschr wcscmp wcscpy wcscspn wcslen wcsncat wcsncmp wcsncpy
 wcspbrk wcsrchr wcsspn wcsstr wcstol wcstombs wcstoul
EOL
	curlibname = nil
	data.each_line { |l|
		list = l.split
		curlibname = list.shift if l[0, 1] != ' '
		list.each { |export| EXPORT[export] = curlibname }
	}
end
end

