#!/usr/bin/ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'test/unit'
require 'rex/exceptions'
require 'rex/proto/dcerpc/ndr'

class Rex::Proto::DCERPC::NDR::UnitTest < Test::Unit::TestCase

	Klass = Rex::Proto::DCERPC::NDR

    def test_align
        assert_equal(Klass.align('').length, 0, 'align 0')
        assert_equal(Klass.align('f').length, 3, 'align 1')
        assert_equal(Klass.align('fo').length, 2, 'align 2')
        assert_equal(Klass.align('foo').length, 1, 'align 3')
        assert_equal(Klass.align('fooo').length, 0, 'align 4')
        assert_equal(Klass.align('foooo').length, 3, 'align 5')
    end

    def test_numbers
        assert_equal(Klass.long(10), "\x0a\x00\x00\x00", 'long')
        assert_equal(Klass.short(10), "\x0a\x00", 'short')
        assert_equal(Klass.byte(10), "\x0a", 'byte')
    end

    def test_conformant_array
        assert_equal(Klass.UniConformantArray('aaaaa').slice(0,9), "\x05\x00\x00\x00aaaaa", 'UniConformantArray')
        assert_equal(Klass.UniConformantArray('aaaaa').length, 12, 'UniConformantArray length')
    end
    
    def test_conformant_string
        assert_equal(Klass.UnicodeConformantVaryingString('aaaaa').slice(0,4+4+4+12), "\x06\x00\x00\x00" + "\x00\x00\x00\x00" + "\x06\x00\x00\x00" "a\x00a\x00a\x00a\x00a\x00\x00\x00", 'UniConformantVaryingString')
        assert_equal(Klass.UnicodeConformantVaryingString('aaaaa').length, 24, 'UniConformantVaryingString length')
        
        assert_equal(Klass.UnicodeConformantVaryingStringPreBuilt('aaaaa').slice(0,4+4+4+6), "\x03\x00\x00\x00" + "\x00\x00\x00\x00" + "\x03\x00\x00\x00" "aaaaa\x00", 'UniConformantVaryingStringPreBuilt')
        assert_equal(Klass.UnicodeConformantVaryingStringPreBuilt('aaaaa').length, 20, 'UniConformantVaryingStringPreBuilt length')
    end

end
