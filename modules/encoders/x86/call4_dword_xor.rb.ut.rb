#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'lib'))
$:.unshift(File.dirname(__FILE__))

require 'test/unit'
require 'rex/ui'
require 'msf/core'
require 'call4_dword_xor'

class Msf::Encoders::X86::Call4Dword::UnitTest < Test::Unit::TestCase

	Klass = Msf::Encoders::X86::Call4Dword

	def test_encoder

		k = Klass.new

		{
			"\x41\x42\x43\x44" => 
				[
					"\x29\xc9\x83\xe9\xff\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76" +
					"\x0e\x66\x30\x86\x84\x83\xee\xfc\xe2\xf4\x27\x72\xc5\xc0",
					0x84863066
				],
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ" =>
				[
					"\x29\xc9\x83\xe9\xf9\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76" +
					"\x0e\xad\x6c\x5d\xb4\x83\xee\xfc\xe2\xf4\xec\x2e\x1e\xf0" +
					"\xe8\x2a\x1a\xfc\xe4\x26\x16\xf8\xe0\x22\x12\xe4\xfc\x3e" +
					"\x0e\xe0\xf8\x3a\x0a\xec\xf4\x36\x5d\xb4",
					0xb45d6cad,
					2
				]
		}.each_pair { |raw, real|
			offset = real[2] || 0

			encoded = k.encode(raw, '', Msf::EncoderState.new(real[1]))

			assert_equal(real[0][offset, -1], encoded[offset, -1])
		}
		
	end

end
