#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/text'
require 'rex/arch/sparc'

class Rex::Arch::Sparc::UnitTest < ::Test::Unit::TestCase

	Klass = Rex::Arch::Sparc

	def test_set
		assert_equal("\x88\x10\x20\x02", Klass.set(0x2, 'g4'))
		assert_equal("\x09\x00\x00\x08\x88\x11\x22\x22", Klass.set(0x2222, 'g4'))
	end

end