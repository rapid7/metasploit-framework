#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'Dev', 'machinetest'))

require 'machinetest'
require 'test/unit'
require 'rex/encoders/xor_d_word'

class Rex::Encoders::XorDWord::UnitTest < ::Test::Unit::TestCase
	Klass = Rex::Encoders::XorDWord
	def klass
		self.class::Klass
	end

	def test_encode
		1000.times {
			buffer = ""
			rand(5000).times { buffer << 0x90 }
			assert_equal(nil, MachineTest.testraw(klass.encode(buffer + "\xcc")))
		}
	end
end
