#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'Dev', 'machinetest'))

require 'test/unit'
require 'rex/encoders/xor_d_word_additive'
require 'rex/encoders/xor_d_word.rb.ut'

class Rex::Encoders::XorDWordAdditive::UnitTest < Rex::Encoders::XorDWord::UnitTest
	Klass = Rex::Encoders::XorDWordAdditive
end
