#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/exploitation/omelet'

class Rex::Exploitation::Omelet::UnitTest < Test::Unit::TestCase

	Klass = Rex::Exploitation::Omelet

	def test_generate
		x = Klass.new('win', ARCH_X86)

		om = x.generate("\xcc" * 1024, '', {
			#:eggsize => 31336,       # default: 123
			#:eggtag => "b00",        # default: 00w
			#:searchforward => false, # default: true
			#:reset => true,          # default: false
			#:startreg => "EBP",      # default: none
			:checksum => true        # default: false
		})
		# XXX: TODO: assertions!
	end

end
