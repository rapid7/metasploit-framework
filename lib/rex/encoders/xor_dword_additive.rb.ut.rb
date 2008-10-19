#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'dev', 'machinetest'))

require 'test/unit'
require 'rex/encoders/xor_dword_additive'
require 'rex/encoders/xor_dword.rb.ut'

class Rex::Encoders::XorDwordAdditive::UnitTest < Rex::Encoders::XorDword::UnitTest
	Klass = Rex::Encoders::XorDwordAdditive
end