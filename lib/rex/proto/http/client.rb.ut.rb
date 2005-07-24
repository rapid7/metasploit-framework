#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/http'

class Rex::Proto::Http::Client::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::Http::Client

	def test_parse
		c = Klass.new('www.google.com')
		r = Rex::Proto::Http::Request::Get.new('/')

		resp = c.send_request(r)

		assert_equal(200, resp.code)
		assert_equal('OK', resp.message)
		assert_equal('1.0', resp.proto)
	end

end
