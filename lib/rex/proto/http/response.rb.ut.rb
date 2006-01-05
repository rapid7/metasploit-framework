#!/usr/bin/env ruby

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
			"Chicken: 47\r\n\r\n", h.to_s, 'to_s w/o body')

        h.body = 'hi mom'
        assert_equal(
			"HTTP/1.1 200 OK\r\n" +
			"Foo: Fishing\r\n" +
			"Content-Length: 6\r\n" +
			"Chicken: 47\r\n\r\nhi mom", h.to_s, 'to_s w/ body')
	end


    def test_chunked
		h = Klass.new

		h.headers['Foo']     = 'Fishing'
		h.headers['Chicken'] = 47
        h.auto_cl = false
		h.transfer_chunked = true


		assert_equal(
			"HTTP/1.1 200 OK\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Foo: Fishing\r\n" +
			"Chicken: 47\r\n\r\n0\r\n\r\n", h.to_s, 'chunked w/o body'
            )
        
        srand(0)
        h.body = Rex::Text.rand_text_alphanumeric(100)
        assert_equal(
            "HTTP/1.1 200 OK\r\n" +
            "Transfer-Encoding: chunked\r\n" +
            "Foo: Fishing\r\n" +
            "Chicken: 47\r\n\r\n" +
            "5\r\nsv1AD\r\n7\r\n7DnJTVy\r\n5\r\nkXGYY\r\n5\r\nM6Bmn\r\n4\r\nXuYR\r\n5\r\nlZNIJ\r\n5\r\nUzQzF\r\n9\r\nPvASjYxzd\r\n5\r\nTTOng\r\n4\r\nBJ5g\r\n8\r\nfK0XjLy3\r\n6\r\nciAAk1\r\n6\r\nFmo0RP\r\n1\r\nE\r\n2\r\npq\r\n6\r\n6f4BBn\r\n4\r\np5jm\r\n1\r\n3\r\n6\r\nLuSbAO\r\n1\r\nj\r\n2\r\n1M\r\n3\r\n5qU\r\n0\r\n\r\n",
            h.to_s, 'random chunk sizes'
            )

        h.chunk_max_size = 1
        h.body = 'hi mom'
        assert_equal(
			"HTTP/1.1 200 OK\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Foo: Fishing\r\n" +
			"Chicken: 47\r\n\r\n" +
            "1\r\nh\r\n1\r\ni\r\n1\r\n \r\n1\r\nm\r\n1\r\no\r\n1\r\nm\r\n0\r\n\r\n", 
            h.to_s, '1 byte chunks'
            )
        
        h.chunk_min_size = 2
        assert_equal(
			"HTTP/1.1 200 OK\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Foo: Fishing\r\n" +
			"Chicken: 47\r\n\r\n" +
            "2\r\nhi\r\n2\r\n m\r\n2\r\nom\r\n0\r\n\r\n",
            h.to_s, '2 byte chunks'
            )

        h = Klass.new(200, 'OK', '1.0')
        h.body = 'hi mom'
        h.auto_cl = false
        h.transfer_chunked = true
        assert_raise(Rex::RuntimeError, 'chunked encoding via 1.0') {
            h.to_s
        }

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
