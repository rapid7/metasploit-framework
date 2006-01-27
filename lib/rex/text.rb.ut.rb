#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..'))

require 'test/unit'
require 'rex/text'

class Rex::Text::UnitTest < Test::Unit::TestCase

	def test_unicode
		assert_equal("a\x00b\x00c\x00", Rex::Text.to_unicode('abc'), 'unicode, little endian')
		assert_equal("\x00a\x00b\x00c", Rex::Text.to_unicode('abc', 1), 'unicode, big endian')
	end

	def test_zlib
		assert_equal("x\234\313\310T\310\315\317\005\000\a\225\002;", Rex::Text.zlib_deflate('hi mom'), 'compress')
		assert_equal('hi mom', Rex::Text.zlib_inflate("x\234\313\310T\310\315\317\005\000\a\225\002;"), 'decompress')
	end

	def test_gzip
		string = Rex::Text.gzip('hi mom')
		assert_equal("\x1f\x8b\x08\x00", string.slice!(0,4), 'gzip headers')
		
		# skip the next 6 bytes as it is host & time specific (zlib's example gun does, so why not us too?)
		string.slice!(0,6)
		
		assert_equal("\xcb\xc8\x54\xc8\xcd\xcf\x05\x00\x68\xa4\x1c\xf0\x06\x00\x00\x00", string, 'gzip data')

		assert_equal('hi mom', Rex::Text.ungzip("\037\213\010\000|\261\275C\002\003\313\310T\310\315\317\005\000h\244\034\360\006\000\000\000"), 'ungzip')
	end

	def test_badchar_index
		assert_equal(nil, Rex::Text.badchar_index('abcdef', 'gzk'))
		assert_equal(2, Rex::Text.badchar_index('123avd', 'ly3'))
	end
	
	def test_hexify
		str = "\x01\x02\xff"
	
		assert_equal("\\x01\\x02\\xff", Rex::Text.to_hex(str), 'to_hex')
		assert_equal("ABC01ABC02ABCff", Rex::Text.to_hex(str, 'ABC'), 'to_hex with prefix')
		assert_equal("\"\\x01\\x02\\xff\"\n", Rex::Text.to_ruby(str), 'to_ruby')
		assert_equal("\"\\x01\\x02\\xff\";\n", Rex::Text.to_perl(str), 'to_perl')
		assert_equal("unsigned char buf[] = \n\"\\x01\\x02\\xff\";\n", Rex::Text.to_c(str), 'to_c')
	
		# 0 -> 20
		str = "\000\001\002\003\004\005\006\a\010\t\n\v\f\r\016\017\020\021\022\023"

		assert_equal("\"\\x00\\x01\\x02\\x03\" +\n\"\\x04\\x05\\x06\\x07\" +\n\"\\x08\\x09\\x0a\\x0b\" +\n\"\\x0c\\x0d\\x0e\\x0f\" +\n\"\\x10\\x11\\x12\\x13\"\n", Rex::Text.to_ruby(str, 20), 'to_ruby with wrap')
		assert_equal("\"\\x00\\x01\\x02\\x03\" .\n\"\\x04\\x05\\x06\\x07\" .\n\"\\x08\\x09\\x0a\\x0b\" .\n\"\\x0c\\x0d\\x0e\\x0f\" .\n\"\\x10\\x11\\x12\\x13\";\n", Rex::Text.to_perl(str, 20), 'to_perl with wrap')
		assert_equal("unsigned char buf[] = \n\"\\x00\\x01\\x02\\x03\\x04\"\n\"\\x05\\x06\\x07\\x08\\x09\"\n\"\\x0a\\x0b\\x0c\\x0d\\x0e\"\n\"\\x0f\\x10\\x11\\x12\\x13\";\n", Rex::Text.to_c(str, 20, "buf"), 'to_c with wrap')
	end

	def test_wordwrap
		txt = "this is a test of the word wrap features"

		assert_equal("this is a \ntest of \nthe word \nwrap \nfeatures\n", Rex::Text.wordwrap(txt, 0, 10))
	end

	def test_transforms
		assert_equal("acbd18db4cc2f85cedef654fccc4a4d8", Rex::Text.md5('foo'))
	end

end
