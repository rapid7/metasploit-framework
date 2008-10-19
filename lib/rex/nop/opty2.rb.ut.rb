#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/nop/opty2'

class Rex::Nop::Opty2::UnitTest < Test::Unit::TestCase

	Klass = Rex::Nop::Opty2

	# TODO: machine test
	def test_opty2
		o = Klass.new

		100.times {
			s = o.generate_sled(100)

			assert_equal(s.length, 100)
		}
	end

end