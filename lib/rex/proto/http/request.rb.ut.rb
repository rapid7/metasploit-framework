#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/http'

class Rex::Proto::Http::Request::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::Http::Request

	def test_to_s
		h = Klass.new

		h.headers['Foo']     = 'Fishing'
		h.headers['Chicken'] = 47
		h.auto_cl = true

		assert_equal(
			"GET / HTTP/1.1\r\n" +
			"Foo: Fishing\r\n" +
			"Content-Length: 0\r\n" +
			"Chicken: 47\r\n\r\n", h.to_s)
	end

	def test_from_s
		h = Klass.new

		h.from_s(
			"POST /foo HTTP/1.0\r\n" +
			"Lucifer: Beast\r\n" +
			"HoHo: Satan\r\n" +
			"Eat: Babies\r\n" +
			"\r\n")

		assert_equal('POST', h.method)
		assert_equal('/foo', h.uri)
		assert_equal('1.0', h.proto)
		assert_equal("POST /foo HTTP/1.0\r\n", h.cmd_string)
		h.method = 'GET'
		assert_equal("GET /foo HTTP/1.0\r\n", h.cmd_string)
		assert_equal('Babies', h['Eat'])
	end

end
