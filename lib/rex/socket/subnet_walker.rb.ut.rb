#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/socket/subnet_walker'

class Rex::Socket::SubnetWalker::UnitTest < Test::Unit::TestCase

	Klass = Rex::Socket::SubnetWalker

	def test_walker
		s = Klass.new('10.0.0.0', '255.255.255.0')

		0.upto(255) { |x|
			assert_equal('10.0.0.' + x.to_s, s.next_ip)
		}
		assert_nil(s.next_ip)

		s.reset

		0.upto(255) { |x|
			assert_equal('10.0.0.' + x.to_s, s.next_ip)
		}
		assert_nil(s.next_ip)
	end

end