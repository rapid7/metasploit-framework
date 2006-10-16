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
	def self.default
		spin
	end

	#
	# Infinite 'hlt' loop.
	#
	def self.spin
		"\xf4\xeb\xfd" 
	end

end

end
end
end
end
