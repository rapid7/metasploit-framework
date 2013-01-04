##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Encoder::XorAdditiveFeedback

	def initialize
		super(
			'Name'             => 'SPARC DWORD XOR Encoder',
			'Description'      => %q{
				This encoder is optyx's 48-byte SPARC encoder with some tweaks.
			},
			'Author'           => [ 'optyx', 'hdm' ],
			'Arch'             => ARCH_SPARC,
			'License'          => MSF_LICENSE,
			'Decoder'          =>
				{
					'KeySize'    => 4,
					'BlockSize'  => 4,
					'KeyPack'    => 'N',
				})
	end

	#
	# Returns the decoder stub
	#
	def decoder_stub(state)
		Rex::Arch::Sparc.set_dword(state.key, 'l1') +
		"\x20\xbf\xff\xff" +   # bn,a  _start - 4
		"\x20\xbf\xff\xff" +   # bn,a  _start
		"\x7f\xff\xff\xff" +   # call  _start + 4
		"\xea\x03\xe0\x20" +   # ld    [%o7 + 0x20],%l7
		"\xaa\x9d\x40\x11" +   # xorcc %l5,%l1,%l5
		"\xea\x23\xe0\x20" +   # st    %l5,[%o7 + 0x20]
		"\xa2\x04\x40\x15" +   # add   %l1,%l5,%l1
		"\x81\xdb\xe0\x20" +   # flush %o7 + 0x20
		"\x12\xbf\xff\xfb" +   # bnz   dec_loop
		"\x9e\x03\xe0\x04"     # add   %o7,4,%o7
	end

	#
	# Append the decoder key now that we're done
	#
	def encode_end(state)
		state.encoded += [ state.key.to_i ].pack('N')
	end

	#
	# Verify that the chosen key doesn't become an invalid byte due to
	# the set_dword() result (22/10 bit split)
	#
	def find_key_verify(buf, key_bytes, badchars)
		return ( has_badchars?(
			Rex::Arch::Sparc.set_dword(key_bytes_to_integer(key_bytes), 'l1'),
			badchars
		) ? false : true)
	end

end
