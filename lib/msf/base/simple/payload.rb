require 'msf/base'

module Msf
module Simple

###
#
# Payload
# -------
#
# Simple payload wrapper class for performing generation.
#
###
class Payload

	#
	# Generate a payload with the mad skillz.  The payload can be generated in
	# a number of ways.
	#
	# opts can have:
	#
	#   Encoder  => A encoder module instance.
	#   Badchars => A string of bad characters.
	#   Format   => The format to represent the data as: ruby, perl, c, raw
	#
	def self.generate(payload, opts)
		# Generate the payload
		buf = payload.generate

		# If an encoder was specified, encode the generated payload
		if (opts['Encoder'])
			buf = opts['Encoder'].encode(buf, opts['Badchars'])
		end

		# Serialize the generated payload to some sort of format
		return Buffer.transform(buf, opts['Format'] || 'raw')
	end

end

end
end
