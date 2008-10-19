#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'dev', 'machinetest'))

require 'machinetest'
require 'test/unit'
require 'rex/encoders/xor_dword'

class Rex::Encoders::XorDword::UnitTest < ::Test::Unit::TestCase
	Klass = Rex::Encoders::XorDword
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