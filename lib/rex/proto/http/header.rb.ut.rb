#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/proto/http'

class Rex::Proto::Http::Packet::Header::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::Http::Packet::Header

	def test_to_s
		h = Klass.new

		h['Foo']     = 'Fishing'
		h['Chicken'] = 47

		assert_equal(
			"Foo: Fishing\r\n" +
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

		assert_equal('Babies', h['Eat'], 'header')
		assert_equal('Satan', h['HoHo'], 'header')
		assert_equal('Satan', h['hOhO'], 'header')

		assert_equal("POST /foo HTTP/1.0\r\n", h.cmd_string, 'cmd_string')
	end

	def test_just_cmdstring
		h = Klass.new

		h.from_s("POST /foo HTTP/1.0")
		assert_equal("POST /foo HTTP/1.0\r\n", h.cmd_string, 'just cmd_string')
	end
end