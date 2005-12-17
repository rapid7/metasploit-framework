#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))

require 'test/unit'
require 'msf/core'
require 'msf/core/recon/entity'

class Msf::Recon::Entity::Host::UnitTest < Test::Unit::TestCase
	
	Klass = Msf::Recon::Entity::Host

	def test_target
		e = Klass.new

		assert_not_nil(e)
		assert_not_nil(e.sys)
		assert_not_nil(e.services)

		e.sys.platform = 4
		assert_equal(4, e.sys.platform)
		e.sys.arch = 4
		assert_equal(4, e.sys.arch)
		e.sys.time = 4
		assert_equal(4, e.sys.time)
	end
end
