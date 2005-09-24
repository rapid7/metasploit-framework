#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..'))

require 'test/unit'
require 'rex/evasion'

class Rex::Evasion::UnitTest < Test::Unit::TestCase

	Klass = Rex::Evasion

	def test_global
		assert_equal(EVASION_NORMAL, Klass.get_level)
		
		Klass.set_level(EVASION_HIGH)
		assert_equal(EVASION_HIGH, Klass.get_level)
		
		Klass.set_level(EVASION_LOW)
		assert_equal(EVASION_LOW, Klass.get_level)
	end

	def test_subsys
		Klass.reset
		
		assert_equal(EVASION_NORMAL, Klass.get_level)
		assert_equal(EVASION_NORMAL, Klass.get_subsys_level('foo'))

		Klass.set_subsys_level('foo', EVASION_HIGH)
		assert_equal(EVASION_HIGH, Klass.get_subsys_level('foo'))
		assert_equal(EVASION_NORMAL, Klass.get_level)

		Klass.set_subsys_level('foo', EVASION_LOW)
		assert_equal(EVASION_LOW, Klass.get_subsys_level('foo'))

		# Registration
		Klass.register_subsys('dog', EVASION_LOW)
		assert_equal(EVASION_LOW, Klass.subsys['dog'])
		Klass.deregister_subsys('dog')
		assert_equal(nil, Klass.subsys['dog'])
	end

end	
