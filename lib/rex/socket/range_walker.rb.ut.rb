#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/socket/range_walker'

class Rex::Socket::RangeWalker::UnitTest < Test::Unit::TestCase

	Klass = Rex::Socket::RangeWalker

	def test_walker
	
		#
		# Single argument
		#
		s = Klass.new('10.0.0.0-10.0.0.255')

		0.upto(255) { |x|
			assert_equal('10.0.0.' + x.to_s, s.next_ip)
		}
		assert_nil(s.next_ip)

		s.reset

		0.upto(255) { |x|
			assert_equal('10.0.0.' + x.to_s, s.next_ip)
		}
		assert_nil(s.next_ip)

		#
		

		#
		# Backwards
		#
		s = Klass.new('10.0.0.255-10.0.0.0')

		0.upto(255) { |x|
			assert_equal('10.0.0.' + x.to_s, s.next_ip)
		}
		assert_nil(s.next_ip)

		#
		# Same address
		#
		s = Klass.new('10.0.0.255-10.0.0.255')
		assert_equal('10.0.0.255', s.next_ip)
		assert_nil(s.next_ip)
		

		
	end

end