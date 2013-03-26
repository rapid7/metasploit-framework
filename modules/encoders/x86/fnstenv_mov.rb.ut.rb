##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'lib'))
$:.unshift(File.dirname(__FILE__))

require 'test/unit'
require 'rex/ui'
require 'msf/core'
require 'fnstenv_mov'

class Metasploit3 < Msf::Test::Unit::TestCase

	Klass = Msf::Encoders::X86::FnstenvMov

	def test_encoder

		k = Klass.new

		{
			"\xcc\xcc\xcc\xcc" =>
				[
					"\x6a\x01\x59\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x3e" +
					"\x33\x75\x05\x83\xeb\xfc\xe2\xf4\xf2\xff\xb9\xc9",
					4
				],
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ" =>
				[
					"\x6a\x07\x59\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73\x13\x39" +
					"\xaf\x73\x32\x83\xeb\xfc\xe2\xf4\x78\xed\x30\x76\x7c\xe9" +
					"\x34\x7a\x70\xe5\x38\x7e\x74\xe1\x3c\x62\x68\xfd\x20\x66" +
					"\x6c\xf9\x24\x6a\x60\xf5\x73\x32",
					4
				]
		}.each_pair { |raw, real|
			offset = real[1] || 0

			encoded = k.encode(raw, '')

			assert_equal(real[0][offset, -1], encoded[offset, -1])
		}

	end

end
