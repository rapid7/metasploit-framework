#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/socket/switch_board'

class Rex::Socket::SwitchBoard::UnitTest < Test::Unit::TestCase

	Klass = Rex::Socket::SwitchBoard

	def test_add
		Klass.flush_routes
		assert_equal(true, Klass.add_route('0.0.0.0', 0, 'foo'))
		assert_equal(false, Klass.add_route('0.0.0.0', 0, 'foo'))
		assert_equal(1, Klass.routes.length)

		assert_equal('0.0.0.0', Klass.routes[0].subnet)
		assert_equal('0.0.0.0', Klass.routes[0].netmask)
		assert_equal(0, Klass.routes[0].bitmask)
		assert_equal('foo', Klass.routes[0].comm)
	end

	def test_remove
		Klass.flush_routes
		assert_equal(true, Klass.add_route('0.0.0.0', 0, 'foo'))
		assert_equal(true, Klass.remove_route('0.0.0.0', 0, 'foo'))
		assert_equal(false, Klass.remove_route('0.0.0.0', 0, 'foo'))
		assert_equal(0, Klass.routes.length)
	end

	def test_best_comm
		Klass.flush_routes
		Klass.add_route('0.0.0.0', 0, 'default')
		Klass.add_route('1.2.3.0', 24, 'spec')

		assert_equal('default', Klass.best_comm('4.5.6.7'))
		assert_equal('spec', Klass.best_comm('1.2.3.7'))
	end

	def test_remove_by_comm
		Klass.flush_routes
		Klass.add_route('1.2.3.0', 24, 'foo')
		Klass.add_route('1.2.4.0', 24, 'dog')

		Klass.remove_by_comm('foo')

		assert_equal('dog', Klass.best_comm('1.2.4.7'))
		assert_nil(Klass.best_comm('1.2.3.7'))
	end

end