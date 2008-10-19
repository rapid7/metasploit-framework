#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..'))

require 'test/unit'
require 'rex/service_manager'

class Rex::ServiceManager::UnitTest < Test::Unit::TestCase

	Klass = Rex::ServiceManager

	def test_svcm
		begin
			c = Klass
			s = c.start(Rex::Proto::Http::Server, 8090)
			assert_not_nil(s)
			t = c.start(Rex::Proto::Http::Server, 8090)
			assert_not_nil(t)
			assert_equal(s, t)
			z = c.start(Rex::Proto::Http::Server, 8091)
			assert_not_equal(t, z)
			assert_equal("HTTP Server", s.alias)
			assert_equal("HTTP Server 1", z.alias)
		ensure
			c.stop_by_alias(s.alias) if (s)
			c.stop_by_alias(z.alias) if (z)
			c.stop_by_alias(t.alias) if (t)
		end

	end

end