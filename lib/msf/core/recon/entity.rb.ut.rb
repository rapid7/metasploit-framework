#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'msf/core'
require 'msf/core/recon/entity'

class Msf::Recon::Entity::UnitTest < Test::Unit::TestCase
	
	Klass = Msf::Recon::Entity

	def test_target
		e = Klass.new

		assert_not_nil(e)

		e.set_attribute('foo', 4)
		assert_not_nil(e.foo)
		assert_equal(4, e.foo)
		assert_equal(4, e.get_attribute('foo'))
		e.set_attribute('foo', 5)
		assert_equal(5, e.foo)
		assert_equal(5, e.get_attribute('foo'))
	end
end
