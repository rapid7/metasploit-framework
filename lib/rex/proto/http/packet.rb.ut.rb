#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/http'

class Rex::Proto::Http::Packet::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::Http::Packet

	def test_parse
		h = Klass.new

		req1 = 
			"GET / HTTP/1.0\r\n" +
			"Foo: Bird\r\n" +
			"Accept: text/html\r\n" +
			"\r\n" + 
			"Super body"

        h.auto_cl = false
        h.parse(req1)
        assert_equal(Klass::ParseCode::Completed, h.parse(req1))
		assert_equal(true, h.completed?)
		assert_equal("Bird", h.headers['Foo'])
		assert_equal("text/html", h.headers['Accept'])
		assert_equal("Super body", h.body);
        assert_equal(req1, h.to_s)
	end

	def test_to_s
		h = Klass.new

		h.headers['Foo']     = 'Fishing'
		h.headers['Chicken'] = 47
		h.auto_cl = true

		assert_equal(
			"Foo: Fishing\r\n" +
			"Content-Length: 0\r\n" +
			"Chicken: 47\r\n\r\n", h.to_s)
	end

	def test_from_s
		h = Klass.new

		h.from_s(
			"HTTP/1.0 200 OK\r\n" +
			"Lucifer: Beast\r\n" +
			"HoHo: Satan\r\n" +
			"Eat: Babies\r\n" +
			"\r\n")

		assert_equal('Babies', h['Eat'])
		h['Eat'] = "fish"
		assert_equal('fish', h['Eat'])
	end

end
