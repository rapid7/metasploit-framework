#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'Dev', 'machinetest'))

require 'test/unit'
require 'Rex/Encoders/XorDWordAdditive'
require 'Rex/Encoders/XorDWord.rb.ut'

class Rex::Encoders::XorDWordAdditive::UnitTest < Rex::Encoders::XorDWord::UnitTest
	Klass = Rex::Encoders::XorDWordAdditive
end
