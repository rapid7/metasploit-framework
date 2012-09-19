#encoding: utf-8
require 'rubygems'
gem 'test-unit'

require 'test/unit'
require 'windows/wide_string'

class TC_WideString < Test::Unit::TestCase
   def setup
      @str_english = WideString.new('hello')
      @str_greek   = WideString.new('Ελλάσ')
   end

   def test_length
      assert_equal(10, @str_english.length)
      assert_equal(10, @str_greek.length)
   end

   def test_size
      assert_equal(5, @str_english.size)
      assert_equal(5, @str_greek.size)
   end

   def test_to_multi
      assert_respond_to(@str_english, :to_multi)
      assert_equal('hello', @str_english.to_multi)
      assert_equal('Ελλάσ', @str_greek.to_multi)
   end

   def test_literal_string_value
      assert_equal("h\000e\000l\000l\000o\000\000\000", @str_english)
      assert_equal("\225\003\273\003\273\003\254\003\303\003\000\000", @str_greek)
   end

   def test_alias_to_s
      assert_respond_to(@str_greek, :to_s)
      assert_true(@str_greek.method(:to_s) == @str_greek.method(:to_multi))
   end

   def test_alias_to_str
      assert_respond_to(@str_greek, :to_str)
      assert_true(@str_greek.method(:to_str) == @str_greek.method(:to_multi))
   end

   def test_alias_inspect
      assert_respond_to(@str_greek, :inspect)
      assert_true(@str_greek.method(:inspect) == @str_greek.method(:to_multi))
   end

   def teardown
      @str_english = nil
      @str_greek   = nil
   end
end
