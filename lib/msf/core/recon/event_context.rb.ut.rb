#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'msf/core'
require 'msf/core/recon/event_context'

class Msf::Recon::EventContext::UnitTest < Test::Unit::TestCase
	
	Klass = Msf::Recon::EventContext

	def test_target
		e = Klass.new

		assert_not_nil(e)
		e.connection = 4
		assert_equal(4, e.connection)
		assert_equal(4, e.get_attribute('connection'))
	end
end
