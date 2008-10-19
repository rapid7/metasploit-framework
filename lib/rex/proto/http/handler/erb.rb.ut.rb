#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))

require 'test/unit'
require 'rex/proto/http'

class Rex::Proto::Http::Handler::Erb::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::Http::Handler::Erb
	Request = Rex::Proto::Http::Request

	def test_erb
		k = Klass.new(nil, File.dirname(__FILE__))
		r = k.on_request(nil, Request::Get.new("/erb.rb.ut.rb.rhtml"))

		assert_not_nil(r)
		assert_equal("foo 4\n", r.body)
	end

end