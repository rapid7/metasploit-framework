#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'rex/exceptions'
require 'rex/encoder/xdr'

class Rex::Encoder::XDR::UnitTest < Test::Unit::TestCase

	def test_encode
		assert_equal("\000\000\004\322", Rex::Encoder::XDR.encode_int(1234), 'encode_int')
		assert_equal("\377\377\377\322", Rex::Encoder::XDR.encode_lchar(1234), 'encode_lchar')
		assert_equal("\000\000\000\003abc\000", Rex::Encoder::XDR.encode_string('abc'), 'encode_string')
		assert_equal("\000\000\000\003abc\000", Rex::Encoder::XDR.encode_string('abc', 4), 'encode_string with maxlen')
		assert_raises(Rex::ArgumentError) {
			Rex::Encoder::XDR.encode_string('abc', 2)
		}
		assert_equal("\000\000\000\003\000\000\000\001\000\000\000\002\000\000\000\003", Rex::Encoder::XDR.encode_varray([1,2,3]) {|i| Rex::Encoder::XDR.encode_int(i) }, 'encode_varray')
		assert_equal("\000\000\000\000\000\000\000\002\000\000\000\000\000\000\000\001\000\000\000\003foo\000\000\000\000\003bar\000", Rex::Encoder::XDR.encode(0, [0, 1], "foo", ["bar", 4]), 'encode')
	end

	def test_decode
		assert_equal(1234, Rex::Encoder::XDR.decode_int!("\000\000\004\322"), 'decode_int!')
		assert_equal('abc', Rex::Encoder::XDR.decode_string!("\000\000\000\003abc\000"), 'decode_string')
		assert_equal([1,2,3], Rex::Encoder::XDR.decode_varray!("\000\000\000\003\000\000\000\001\000\000\000\002\000\000\000\003") { |i| Rex::Encoder::XDR.decode_int!(i) } , 'decode_varray!')
		assert_equal(1234, Rex::Encoder::XDR.decode_lchar!("\377\377\377\322"), 'decode_lchar!')
	end
end