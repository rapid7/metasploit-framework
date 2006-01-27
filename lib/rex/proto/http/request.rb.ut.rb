#!/usr/bin/env ruby

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

		assert_equal('POST', h.method, 'method')
		assert_equal('/foo', h.uri, 'uri')
		assert_equal('1.0', h.proto, 'proto')
		assert_equal('Babies', h['Eat'], 'header')

		assert_equal("POST /foo HTTP/1.0\r\n", h.cmd_string, 'cmd_string')

		h.method = 'GET'
		assert_equal("GET /foo HTTP/1.0\r\n", h.cmd_string, 'set method')

		h.uri = '/bar'
		assert_equal("GET /bar HTTP/1.0\r\n", h.cmd_string, 'set uri')

		h.proto = '1.2'
		assert_equal("GET /bar HTTP/1.2\r\n", h.cmd_string, 'set proto')
	end

	def test_params
		h = Klass.new
		h.from_s("GET /foo?a=1&b=2 HTTP/1.0\r\n" +
			"Foo: Bar\r\n\r\n")
		assert_equal('GET', h.method, 'method')
		assert_equal('1.0', h.proto, 'proto')
		assert_equal('Bar', h['Foo'], 'header')
		assert_equal('/foo?a=1&b=2', h.uri, 'uri')

		h.uri_parts['QueryString']['c'] = '3'
		assert_equal('/foo?a=1&b=2&c=3', h.uri, 'uri with additional params')
		
		h.uri_parts['QueryString']['d'] = '='
		assert_equal('/foo?a=1&b=2&c=3&d=%3d', h.uri, 'uri with additional params that require escaping')

		srand(0)
		h.junk_directories = 1
		assert_equal('/D/../DnJT/../kXG/../Y/../BmnXu/../foo?a=1&b=2&c=3&d=%3d', h.uri, 'uri with junk directories')
		
		h.junk_slashes = 1
		assert_equal('/lZ//..//J//../zQzFP///..///S/..//Yxzd//../D/OngB/..///gf//..///XjL//..///ciA/..///k/..//..//RPEpq//../fBB/../jm/../uSbA/..//MqUL/..///DnJT///vDMko//..//jXPNV//..///x//..//jA/..//x///..//..//iwdDi/../Nwn//..//AK///..//rXC///..///ij//..///kXG///SujU/..//yb//..//Bk///..//Wro//..//CzQg///../..//uqzo/..//C//..///eirN/..///o/..///T/..///Y/CDs/../E/..//tLWN///../tL/..//Q///..//../QT/../og/../GVfNH//../Y///..///So///../BmnXu/Bf///../YYDSv///..///qMmj/..//gLoU//..//rlc/../..//bTZ/../uUdD//..///nJJp///../uays///..//fJKb//..///foo?a=1&b=2&c=3&d=%3d', h.uri, 'uri with junk directories')

		h = Klass.new
		h.from_s("GET /foo?a=1&b=2 HTTP/1.0\r\n" + "Foo: Bar\r\n\r\n")
		h.junk_params = 1
		assert_equal("/foo?zerStXB=qweQajx&JsNGmnINHQWPZIj=RHUZCQy&XYEksxXeZUhlXbdhzz=HpxJATk&UwDqBU=EQwvK&oebrfUGJbvjTMSxKih=MkBx&a=1&YkjFGDiohcEa=t&JFhHeIUH=VbsD&UHTfAFbreJT=VlcIruAo&mZKziXgT=z&hsytpEdbRjC=tPkpE&b=2&NetXijJaaWMPiazmuQvoAKL=HeGtePpmrSHcBpCycO&bkfdyudyhM=pQCIzKwabBAFYiPDulrTYGUGczGCccmlFtJkN&fRjtzIZVtlWQZulBFGMaKOIHtF=qDKybZDOSFERFeYDFokxYhShOxHruwhRdMugizXZuyrpuAMJSEHD&MltwtSzxHaxudDKUqBUQq=caXwCmJCspZkaEpKMohlnghajZyYSUecISZYnqcYSDsTtAKDGbjGTiy&mUrAktpChMPhXMFmBKGGmmL=VyyzCMdJzIFrBrPMvMVSZNecspVGkwoaeFPllxfgwQgKMdAdanWTFkT" ,h.uri, 'junk params')

		h = Klass.new
		h.from_s("GET /foo?a=1&b=2 HTTP/1.0\r\n" + "Foo: Bar\r\n\r\n")
		h.junk_self_referring_directories = 1
		assert_equal("/./foo?a=1&b=2", h.uri, 'junk self referring directories')
	end
end
