#!/usr/bin/ruby

$:.unshift(File.join('..', '..', File.dirname(__FILE__)))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'Dev', 'machinetest'))

require 'machinetest'
require 'test/unit'
require 'Rex/Encoders/XorDWord'

class Rex::Encoders::XorDWord::UnitTest < ::Test::Unit::TestCase
	Klass = Rex::Encoders::XorDWord
	def test_encode
		2000.times {
			buffer = ""
			rand(100).times { buffer << 0x90 }
			assert_equal(nil, MachineTest.test(Klass.encode(buffer + "\xcc")))
		}
	end
end
