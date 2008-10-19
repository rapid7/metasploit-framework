#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/test'
require 'rex/exceptions'
require 'rex/proto/dcerpc/ndr'

class Rex::Proto::DCERPC::NDR::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::DCERPC::NDR

	def test_align
		assert_equal(0, Klass.align('').length, 'align 0')
		assert_equal(3, Klass.align('f').length, 'align 1')
		assert_equal(2, Klass.align('fo').length, 'align 2')
		assert_equal(1, Klass.align('foo').length, 'align 3')
		assert_equal(0, Klass.align('fooo').length, 'align 4')
		assert_equal(3, Klass.align('foooo').length, 'align 5')
	end

	def test_numbers
		assert_equal("\x0a\x00\x00\x00", Klass.long(10), 'long')
		assert_equal("\x0a\x00", Klass.short(10), 'short')
		assert_equal("\x0a", Klass.byte(10), 'byte')
	end

	def test_conformant_array
		assert_equal("\x05\x00\x00\x00aaaaa", Klass.UniConformantArray('aaaaa').slice(0,9), 'UniConformantArray')
		assert_equal(12, Klass.UniConformantArray('aaaaa').length, 'UniConformantArray length')
	end
	
	def test_conformant_string
		assert_equal("\x06\x00\x00\x00" + "\x00\x00\x00\x00" + "\x06\x00\x00\x00" "a\x00a\x00a\x00a\x00a\x00\x00\x00", Klass.UnicodeConformantVaryingString('aaaaa').slice(0,4+4+4+12), 'UniConformantVaryingString')
		assert_equal(24, Klass.UnicodeConformantVaryingString('aaaaa').length, 'UniConformantVaryingString length')
	
		assert_equal("\x02\x00\x00\x00" + "\x00\x00\x00\x00" + "\x02\x00\x00\x00" "aa\x00\x00", Klass.UnicodeConformantVaryingStringPreBuilt('aa' + "\x00\x00"), 'UniConformantVaryingStringPreBuilt')
		assert_equal(16, Klass.UnicodeConformantVaryingStringPreBuilt('aa' + "\x00\x00").length, 'UniConformantVaryingStringPreBuilt length')
	end

end