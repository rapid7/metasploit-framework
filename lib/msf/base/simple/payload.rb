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
	#   Encoder   => A encoder module instance.
	#   Badchars  => A string of bad characters.
	#   Format    => The format to represent the data as: ruby, perl, c, raw
	#   Options   => A hash of options to set.
	#   OptionStr => A string of options in VAR=VAL form separated by
	#                whitespace.
	#   NoComment => Disables prepention of a comment
	#
	# raises:
	#
	#   BadcharError => If the supplied encoder fails to encode the payload
	#   NoKeyError => No valid encoder key could be found
	#   ArgumentParseError => Options were supplied improperly
	#
	def self.generate(payload, opts)
		# If options were supplied, import them into the payload's
		# datastore
		if (opts['Option'])
			payload.datastore.import_options_from_hash(opts['Options'])
		elsif (opts['OptionStr'])
			payload.datastore.import_options_from_s(opts['OptionStr'])
		end

		# Generate the payload
		buf = payload.generate

		# If an encoder was specified, encode the generated payload
		if (opts['Encoder'])
			buf = opts['Encoder'].encode(buf, opts['Badchars'])
		end

		fmt = opts['Format'] || 'raw'

		# Save off the original payload length
		len = buf.length

		# Serialize the generated payload to some sort of format
		buf = Buffer.transform(buf, fmt)

		# Prepend a comment
		if (fmt != 'raw' and opts['NoComment'] != true)
			((ds = payload.datastore.to_s) and ds.length > 0) ? ds += "\n" : ds = ''
			
			buf = Buffer.comment(
				"#{payload.refname} - #{len} bytes - http://www.metasploit.com\n" +
				"#{ds}" + 
				((opts['Encoder']) ? "Encoder=" + opts['Encoder'].refname + "\n" : ''), fmt) + buf
		end

		return buf
	end

end

end
end
