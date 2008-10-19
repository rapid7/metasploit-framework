#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))

require 'test/unit'
require 'rex/proto/http'

class Rex::Proto::Http::Handler::Proc::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::Http::Handler::Proc
	Request = Rex::Proto::Http::Request

	def test_proc
		cool = 0
		k = Klass.new(nil, Proc.new { |cli, req|
			cool = 1
		})
			
		r = k.on_request(nil, Request::Get.new("/erb.rb.ut.rb.rhtml"))

		assert_equal(1, cool)
	end

end