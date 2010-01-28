#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/test'
require 'rex/proto/drda/constants'

class Rex::Proto::DRDA::Constants::UnitTest < Test::Unit::TestCase
	
	Konst = Rex::Proto::DRDA::Constants

	def test_defines
		assert_equal(Konst::EXCSAT, 0x1041)
		assert_equal(Konst::MGRLVLLS, 0x1404)
		assert_equal(Konst::SECCHKCD, 0x11a4)
	end

	def test_const_values
		assert_kind_of(Array, Konst.const_values)
		assert Konst.const_values.include? Konst::EXCSAT
	end
	
end
