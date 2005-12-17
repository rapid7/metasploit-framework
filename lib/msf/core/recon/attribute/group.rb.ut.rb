#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))

require 'test/unit'
require 'msf/core'
require 'msf/core/recon/attribute/group'

class Msf::Recon::Attribute::Group::UnitTest < Test::Unit::TestCase
	
	Klass = Msf::Recon::Attribute::Group

	class Tester < Klass
		def_attr :testing
	end

	def test_target
		e = Tester.new

		assert_not_nil(e)

		e.testing = 1
		assert_equal(1, e.testing)
		assert_equal(1, e.get_attribute('testing'))
	end
end
