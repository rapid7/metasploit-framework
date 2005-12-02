#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/http'

class Rex::Proto::Http::Response::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::Http::Response

	def test_to_s
		h = Klass.new

		h.headers['Foo']     = 'Fishing'
		h.headers['Chicken'] = 47
		h.auto_cl = true

		assert_equal(
			"HTTP/1.1 200 OK\r\n" +
			"Foo: Fishing\r\n" +
			"Content-Length: 0\r\n" +
			"Chicken: 47\r\n\r\n", h.to_s)
	end

	def test_from_s
		h = Klass.new

		h.from_s(
			"HTTP/1.0 404 File not found\r\n" +
			"Lucifer: Beast\r\n" +
			"HoHo: Satan\r\n" +
			"Eat: Babies\r\n" +
			"\r\n")

		assert_equal(404, h.code)
		assert_equal('File not found', h.message)
		assert_equal('1.0', h.proto)
		assert_equal("HTTP/1.0 404 File not found\r\n", h.cmd_string)
		h.code = 470
		assert_equal("HTTP/1.0 470 File not found\r\n", h.cmd_string)
		assert_equal('Babies', h['Eat'])
	end

end
