require 'msf/base'

module Msf
module Simple

###
#
# Nop
# ---
#
# Simple nop wrapper class for performing generation.
#
###
class Nop

	#
	# Generate a nop sled, optionally with a few parameters.
	#
	# opts can have any of the standard nop generate sled options
	# as well as:
	#
	#   Format => The format to represent the data as: ruby, perl, c, raw
	#
	def self.generate(nop, length, opts)
		# Generate the nop sled using the options supplied
		buf = nop.generate_sled(length, opts)

		# Serialize the generated payload to some sort of format
		return Buffer.transform(buf, opts['Format'] || 'raw')
	end

end

end
end
