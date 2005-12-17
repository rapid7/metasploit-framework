#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'lib'))
$:.unshift(File.dirname(__FILE__))

require 'test/unit'
require 'rex/ui'
require 'msf/core'
require 'jmp_call_additive'

class Msf::Encoders::X86::JmpCallAdditive::UnitTest < Test::Unit::TestCase

	Klass = Msf::Encoders::X86::JmpCallAdditive

	def test_encoder

		k = Klass.new

		{
			"\x41\x42\x43\x44" => 
				[
					"\xfc\xbb\x99\x65\xdb\xf5\xeb\x0c\x5e\x56\x31\x1e\xad\x01" +
					"\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\xd8\x27\x98" +
					"\xb1\332\247\036:",
					0xf5db6599
				],
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ" =>
				[
					"\xfc\xbb\xb7\x2c\xb5\x03\xeb\x0c\x5e\x56\x31\x1e\xad\x01" +
					"\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\xf6\x6e\xf6" +
					"\x47\xbd\x28\xbf\x0f\x74\xff\x74\xdc\xcb\xb1\xc5\x8c\x82" +
					"\x1f\x89\x78\x71\xf6\x7a\xd9\x20\xac\x84\xd9\322P\205\331",
					0x03b52cb7
				]
		}.each_pair { |raw, real|
			encoded = k.encode(raw, '', Msf::EncoderState.new(real[1]))

			assert_equal(real[0], encoded)
		}
		
	end

end
