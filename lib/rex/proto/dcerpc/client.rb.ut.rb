#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/dcerpc/client'

class Rex::Proto::DCERPC::Client::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::DCERPC::Client

	def test_parse
		
	end

end
