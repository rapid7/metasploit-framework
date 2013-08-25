# -*- coding: binary -*-
require 'rex/arch/x86'
require 'rex/nop/opty2_tables'

module Rex
module Nop

###
#
# This class provides an interface to generating multi-byte NOP sleds for x86.
# Optyx and spoonm get the creds!
#
###
class Opty2

	Table = Rex::Nop::Opty2Tables::StateTable

	def initialize(badchars = '', save_registers = nil)
		self.badchars       = badchars
		self.save_registers = (save_registers || []) | [ 'esp', 'ebp']
	end

	#
	# Generates the Opty2 multi-byte NOP sled.
	#
	def generate_sled(length)
		return '' if (length <= 0)

		# Initialize the sled buffer, the previous state, and the current stream
		# length.
		sled = ''
		prev = 256
		slen = 0

		# Initialize the byte count array
		counts = []

		256.times { |idx| counts[idx] = 0 }

		# Initialize the bad register mask
		mask = 0

		save_registers.each { |reg|
			mask |= 1 << (Rex::Arch::X86.reg_number(reg))
		}
		mask = mask << 16

		# Initialize the bad byte lookup table
		bad_bytes = []
		(badchars || '').each_byte { |byte|
			bad_bytes[byte] = 1
		}

		# Build the sled
		while (length > 0)
			low  = -1
			lows = []

			Table[prev].each { |nt|
				nt.each { |e|
					# Skip it if it's masked off or too large
					next if ((e & mask) != 0)
					next if (((e >> 8) & 0xff) > slen)

					byte = e & 0xff

					# Skip it if it's a bad byte
					next if (bad_bytes[byte] == 1)

					# Use it if it's a better value
					if ((low == -1) or (low > counts[byte]))
						low  = counts[byte]
						lows = [byte]
					# Otherwise, if it's just as good..
					elsif (low == counts[byte])
						lows << byte
					end
				}
			}

			# If we didn't find at least one byte possibility, then we're stuck.
			# Abort.
			if (low == -1)
				raise RuntimeError, "Failed to find a valid byte."
			end

			# Pick a random character for the possiblities
			prev = lows[rand(lows.length)]

			# Increment its used count
			counts[prev] += 1

			# Prepend the byte to the sled
			sled = prev.chr + sled

			# Increment the sled length
			slen   += 1
			length -= 1
		end

		# Return the sled
		sled
	end

	attr_accessor :badchars, :save_registers # :nodoc:
end

end
end
