#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..'))

require 'test/unit'
require 'rex/text'
require 'rex/exceptions'
class Rex::Text::UnitTest < Test::Unit::TestCase

	def test_uri_encode
		srand(0)
		assert_equal('A1%21', Rex::Text.uri_encode('A1!'), 'uri encode')
		assert_equal('A1!', Rex::Text.uri_encode('A1!', 'none'), 'uri encode: none')
		assert_equal('A1%21', Rex::Text.uri_encode('A1!', 'hex-normal'), 'uri encode: hex-normal')
		assert_equal('%41%31%21', Rex::Text.uri_encode('A1!', 'hex-all'), 'uri encode: hex-all')
		assert_equal('A1%u01c3', Rex::Text.uri_encode('A1!', 'u-normal'), 'uri encode: u-normal')
		assert_equal('%uff21%u2081%uff01', Rex::Text.uri_encode('A1!', 'u-all'), 'uri encode: u-all')
		srand(0)
		assert_equal("%uff2d%uff49%uff43%uff52%uff4f%uff53%uff4f%uff46%uff54%u2004%uff45%uff4e%uff43%uff4f%uff44%uff49%uff4e%uff47%u3000%uff44%uff52%uff49%uff56%uff45%uff53%u2005%uff4d%uff45%u2000%uff43%uff52%uff41%uff5a%uff59%uff01", Rex::Text.uri_encode('Microsoft encoding drives me crazy!', 'u-half'))

		assert_raises(TypeError) {
			Rex::Text.uri_encode('a', 'umpa lumpa')
		}
	end

    def test_html_encode
        assert_equal('&#x41', Rex::Text.html_encode('A'), 'html_encode default')
        assert_equal('&#x41', Rex::Text.html_encode('A','hex'), 'html_encode hex')
        assert_equal('&#65', Rex::Text.html_encode('A','int'), 'html_encode int')
        assert_equal('&#0000065', Rex::Text.html_encode('A','int-wide'), 'html_encode int-wide')

        assert_raises(TypeError) {
            Rex::Text.html_encode('a', 'umpa lumpa')
        }
    end

	def test_rand_text
		srand(0)
		assert_equal("\254/u\300C\373\303g\t\323", Rex::Text.rand_text(10), 'rand text 1')
		assert_equal("\025\362$WF\330X\214:\301", Rex::Text.rand_text(10), 'rand text 2')
		assert_equal("\346'W\256XQ\245\031MH", Rex::Text.rand_text(10), 'rand text 3')
		assert_equal('bababbabba', Rex::Text.rand_text(10, nil, 'ab'), 'rand text with specified "good"')
		assert_equal('MA', Rex::Text.rand_state(), 'rand state')
		assert_equal('xzdttongb.5gfk0xjly3.aak.fmo0rp.com', Rex::Text.rand_hostname(), 'rand hostname')
	end


	def test_unicode
		assert_equal("a\x00b\x00c\x00", Rex::Text.to_unicode('abc'), 'unicode, default = little endian')
		assert_equal("a\x00b\x00c\x00", Rex::Text.to_unicode('abc', 'utf-16le'), 'utf-16le')
		assert_equal("\x00a\x00b\x00c", Rex::Text.to_unicode('abc', 'utf-16be'), 'utf-16be')
		assert_equal("a\x00\x00\x00b\x00\x00\x00c\x00\x00\x00", Rex::Text.to_unicode('abc', 'utf-32le'), 'utf-32le')
		assert_equal("\x00\x00\x00a\x00\x00\x00b\x00\x00\x00c", Rex::Text.to_unicode('abc', 'utf-32be'), 'utf-32be')
		assert_equal("abc+-abc-+AAA-", Rex::Text.to_unicode("abc+abc-\x00", 'utf-7'), 'utf-7')
		assert_equal("+AGE-+AGI-+AGM-+ACs-+AGE-+AGI-+AGM-+AC0-+AAA-", Rex::Text.to_unicode("abc+abc-\x00", 'utf-7', 'all'), 'utf-7-all')

		assert_equal("a\303\272", Rex::Text.to_unicode("a\xFA", 'utf-8'))
		assert_equal("\xC1\xA1", Rex::Text.to_unicode('a', 'utf-8', 'overlong', 2), 'utf-8 overlong')
		assert_equal("\xE0\x81\xA1", Rex::Text.to_unicode('a', 'utf-8', 'overlong', 3), 'utf-8 overlong')
		assert_equal("\xF0\x80\x81\xA1", Rex::Text.to_unicode('a', 'utf-8', 'overlong', 4), 'utf-8 overlong')
		assert_equal("\xF8\x80\x80\x81\xA1", Rex::Text.to_unicode('a', 'utf-8', 'overlong', 5), 'utf-8 overlong')
		assert_equal("\xFC\x80\x80\x80\x81\xA1", Rex::Text.to_unicode('a', 'utf-8', 'overlong', 6), 'utf-8 overlong')
		assert_equal("\xFE\x80\x80\x80\x80\x81\xA1", Rex::Text.to_unicode('a', 'utf-8', 'overlong', 7), 'utf-8 overlong')
		100.times {
			assert(["\xC1\x21","\xC1\x61","\xC1\xE1"].include?(Rex::Text.to_unicode('a', 'utf-8', 'invalid')), 'utf-8 invalid')
			assert(["\xE0\x01\x21","\xE0\x01\x61","\xE0\x01\xA1","\xE0\x01\xE1","\xE0\x41\x21","\xE0\x41\x61","\xE0\x41\xA1","\xE0\x41\xE1","\xE0\x81\x21","\xE0\x81\x61","\xE0\x81\xA1","\xE0\x81\xE1","\xE0\xC1\x21","\xE0\xC1\x61","\xE0\xC1\xA1","\xE0\xC1\xE1"].include?(Rex::Text.to_unicode('a', 'utf-8', 'invalid', 3)), 'utf-8 invalid 3 byte')
		}

		a = ["\xC1\x21","\xC1\x61","\xC1\xE1"]
		10.times {
			encoded = Rex::Text.to_unicode('a', 'utf-8', 'invalid')
			if a.include?(encoded)
				a.delete(encoded)
			end
		}
		assert_equal([], a, 'all possible values')

		assert_raises(TypeError) {
			Rex::Text.to_unicode('a', 'utf-8', '', 8)
		}
		assert_raises(TypeError) {
			Rex::Text.to_unicode('a', 'utf-8', 'foo', 6)
		}

		assert_raises(TypeError) {
			Rex::Text.to_unicode('a', 'uhwtfms', -1)
		}

		100.times {
			assert(["\x01\x00","\x01\x02","\x01\x04","\x01\xcd","\x01\xde","\xff\x21"].include?(Rex::Text.to_unicode('A', 'uhwtfms')), 'uhwtfms')
			assert(["\x00\xc0","\x00\xc1","\x00\xc2","\x00\xc3","\x00\xc4","\x00\xc5"].include?(Rex::Text.to_unicode('A', 'uhwtfms', 949)), 'uhwtfms codepage 949')
		}

		a = ["\x01\x00","\x01\x02","\x01\x04","\x01\xcd","\x01\xde","\xff\x21"]
		20.times {
			encoded = Rex::Text.to_unicode('A', 'uhwtfms')
			if a.include?(encoded)
				a.delete(encoded)
			end
		}
		assert_equal([], a, 'all possible values uhwtfms')
		
		assert_raises(TypeError) {
			Rex::Text.to_unicode('a', 'uhwtfms-half', 1)
		}

		assert_equal("\xFF\x01", Rex::Text.to_unicode('!', 'uhwtfms-half'))
		srand(0)
		assert_equal("\xff\x2d\xff\x49\xff\x43\xff\x52\xff\x4f\xff\x53\xff\x4f\xff\x46\xff\x54\x20\x04\xff\x45\xff\x4e\xff\x43\xff\x4f\xff\x44\xff\x49\xff\x4e\xff\x47\x30\x00\xff\x44\xff\x52\xff\x49\xff\x56\xff\x45\xff\x53\x20\x05\xff\x4d\xff\x45\x20\x00\xff\x43\xff\x52\xff\x41\xff\x5a\xff\x59\xff\x01", Rex::Text.to_unicode('Microsoft encoding drives me crazy!', 'uhwtfms-half'))
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
		str = "\x01\x02\xff\x00"
	
		assert_equal("\\x01\\x02\\xff\\x00", Rex::Text.to_hex(str), 'to_hex')
		assert_equal("ABC01ABC02ABCffABC00", Rex::Text.to_hex(str, 'ABC'), 'to_hex with prefix')
		assert_equal('%u0102%uff00', Rex::Text.to_hex(str, '%u', 2), 'to_hex with chunk size of 2')
		
		# to_hex, without providing enouigh data to chunk on a given size
		assert_raises(RuntimeError){ Rex::Text.to_hex('a', '', 2) }

		assert_equal("buf = \n\"\\x01\\x02\\xff\\x00\"\n", Rex::Text.to_ruby(str), 'to_ruby')
		assert_equal("my $buf = \n\"\\x01\\x02\\xff\\x00\";\n", Rex::Text.to_perl(str), 'to_perl')
		assert_equal("unsigned char buf[] = \n\"\\x01\\x02\\xff\\x00\";\n", Rex::Text.to_c(str), 'to_c')
	
		# 0 -> 20
		str = "\000\001\002\003\004\005\006\a\010\t\n\v\f\r\016\017\020\021\022\023"

		assert_equal("buf = \n\"\\x00\\x01\\x02\\x03\" +\n\"\\x04\\x05\\x06\\x07\" +\n\"\\x08\\x09\\x0a\\x0b\" +\n\"\\x0c\\x0d\\x0e\\x0f\" +\n\"\\x10\\x11\\x12\\x13\"\n", Rex::Text.to_ruby(str, 20), 'to_ruby with wrap')
		assert_equal("my $buf = \n\"\\x00\\x01\\x02\\x03\" .\n\"\\x04\\x05\\x06\\x07\" .\n\"\\x08\\x09\\x0a\\x0b\" .\n\"\\x0c\\x0d\\x0e\\x0f\" .\n\"\\x10\\x11\\x12\\x13\";\n", Rex::Text.to_perl(str, 20), 'to_perl with wrap')
		assert_equal("unsigned char buf[] = \n\"\\x00\\x01\\x02\\x03\\x04\"\n\"\\x05\\x06\\x07\\x08\\x09\"\n\"\\x0a\\x0b\\x0c\\x0d\\x0e\"\n\"\\x0f\\x10\\x11\\x12\\x13\";\n", Rex::Text.to_c(str, 20, "buf"), 'to_c with wrap')
		assert_equal("\\x0a", Rex::Text.to_hex("\n"), 'to_hex newline')
	end

	def test_wordwrap
		txt = "this is a test of the word wrap features"

		assert_equal("this is a \ntest of \nthe word \nwrap \nfeatures\n", Rex::Text.wordwrap(txt, 0, 10))
	end

	def test_transforms
		assert_equal("acbd18db4cc2f85cedef654fccc4a4d8", Rex::Text.md5('foo'))
	end

end
