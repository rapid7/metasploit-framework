require 'msf/base'

module Msf
module Simple

###
#
# Simple payload wrapper class for performing generation.
#
###
module Payload

	include Module

	#
	# Generate a payload with the mad skillz.  The payload can be generated in
	# a number of ways.
	#
	# opts can have:
	#
	#   Encoder     => A encoder module name.
	#   BadChars    => A string of bad characters.
	#   Format      => The format to represent the data as: ruby, perl, c, raw
	#   Options     => A hash of options to set.
	#   OptionStr   => A string of options in VAR=VAL form separated by
	#                  whitespace.
	#   NoComment   => Disables prepention of a comment
	#   NopSledSize => The number of NOPs to use
	#   MaxSize     => The maximum size of the payload.
	#
	# raises:
	#
	#   BadcharError => If the supplied encoder fails to encode the payload
	#   NoKeyError => No valid encoder key could be found
	#   ArgumentParseError => Options were supplied improperly
	#
	def self.generate_simple(payload, opts)

		# Import any options we may need
		payload._import_extra_options(opts)

		# Generate the payload
		e = EncodedPayload.create(payload,
				'BadChars' => opts['BadChars'],
				'MinNops'  => opts['NopSledSize'],
				'Encoder'  => opts['Encoder'],
				'Space'    => opts['MaxSize'])

		fmt = opts['Format'] || 'raw'

		# Save off the original payload length
		len = e.encoded.length

		# Serialize the generated payload to some sort of format
		buf = Buffer.transform(e.encoded, fmt)

		# Prepend a comment
		if (fmt != 'raw' and opts['NoComment'] != true)
			((ou = payload.options.options_used_to_s(payload.datastore)) and ou.length > 0) ? ou += "\n" : ou = ''
			buf = Buffer.comment(
				"#{payload.refname} - #{len} bytes#{payload.staged? ? " (stage 1)" : ""}\n" +
				"http://www.metasploit.com\n" +
				((e.encoder) ? "Encoder: #{e.encoder.refname}\n" : '') +
				((e.nop) ?     "NOP gen: #{e.nop.refname}\n" : '') +
				"#{ou}",
				fmt) + buf

			# If it's multistage, include the second stage too
			if payload.staged?
				stage = payload.generate_stage

				# If a stage was generated, then display it
				if stage and stage.length > 0
					buf +=
						"\n" +
						Buffer.comment(
						"#{payload.refname} - #{stage.length} bytes (stage 2)\n" +
						"http://www.metasploit.com\n",
						fmt) + Buffer.transform(stage, fmt)
				end
			end

		end

		return buf
	end

	#
	# Calls the class method.
	#
	def generate_simple(opts)
		Msf::Simple::Payload.generate_simple(self, opts)
	end

end

end
end