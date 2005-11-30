#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/dcerpc/response'
	
class Rex::Proto::DCERPC::Response::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::DCERPC::Response

	def test_parse

	end
end
