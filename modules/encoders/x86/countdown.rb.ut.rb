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
require 'countdown'

class Metasploit3 < Msf::Test::Unit::TestCase

	Klass = Msf::Encoders::X86::Countdown

	def test_encoder

		k = Klass.new

		{
			"\xcc\xcc\xcc\xcc" =>
				[
					"\x6a\x03\x59\xe8\xff\xff\xff\xff\xc1\x5e\x30\x4c\x0e\x07" +
					"\xe2\xfa\xcd\xce\xcf\xc8",
					4
				],
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ" =>
				[
					"\x6a\x19\x59\xe8\xff\xff\xff\xff\xc1\x5e\x30\x4c\x0e\x07" +
					"\xe2\xfa\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40" +
					"\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40\x40",
					4
				]
		}.each_pair { |raw, real|
			offset = real[1] || 0

			encoded = k.encode(raw, '')

			assert_equal(real[0][offset, -1], encoded[offset, -1])
		}

	end

end
