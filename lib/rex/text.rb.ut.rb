#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..'))

require 'test/unit'
require 'rex/text'

class Rex::Text::UnitTest < Test::Unit::TestCase

	def test_hexify
		str = "\x01\x02\xff"
		
		assert_equal("\"\\x01\\x02\\xff\"\n", Rex::Text.to_ruby(str))
		assert_equal("\"\\x01\\x02\\xff\";\n", Rex::Text.to_perl(str))
		assert_equal("unsigned char buf[] = \n\"\\x01\\x02\\xff\";\n", Rex::Text.to_c(str))
	
		# 0 -> 20
		str = "\000\001\002\003\004\005\006\a\010\t\n\v\f\r\016\017\020\021\022\023"

		assert_equal("\"\\x00\\x01\\x02\\x03\" +\n\"\\x04\\x05\\x06\\x07\" +\n\"\\x08\\x09\\x0a\\x0b\" +\n\"\\x0c\\x0d\\x0e\\x0f\" +\n\"\\x10\\x11\\x12\\x13\"\n", Rex::Text.to_ruby(str, 20))
		assert_equal("\"\\x00\\x01\\x02\\x03\" .\n\"\\x04\\x05\\x06\\x07\" .\n\"\\x08\\x09\\x0a\\x0b\" .\n\"\\x0c\\x0d\\x0e\\x0f\" .\n\"\\x10\\x11\\x12\\x13\";\n", Rex::Text.to_perl(str, 20))
		assert_equal("unsigned char buf[] = \n\"\\x00\\x01\\x02\\x03\\x04\"\n\"\\x05\\x06\\x07\\x08\\x09\"\n\"\\x0a\\x0b\\x0c\\x0d\\x0e\"\n\"\\x0f\\x10\\x11\\x12\\x13\";\n", Rex::Text.to_c(str, 20, "buf"))
	end

	def test_wordwrap
		txt = "this is a test of the word wrap features"

		assert_equal("this is a \ntest of \nthe word \nwrap \nfeatures\n", Rex::Text.wordwrap(txt, 0, 10))
	end

	def test_transforms
		assert_equal("acbd18db4cc2f85cedef654fccc4a4d8", Rex::Text.md5('foo'))
	end

end
