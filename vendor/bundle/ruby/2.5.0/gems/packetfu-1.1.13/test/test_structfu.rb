#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'test/unit'
$:.unshift File.join(File.expand_path(File.dirname(__FILE__)), "..", "lib")
require 'packetfu'

# Whee unit testing.
class IntStringTest < Test::Unit::TestCase
  include StructFu

  def test_intstring_len
    s = IntString.new("hello!", Int32)
    assert_equal(s.len, s.int.v)
    assert_not_equal(s.len, s.length)
    s.len=10
    assert_equal(s.len, s[:int][:value])
  end

  def test_intstring_to_s
    s = IntString.new("hello!", Int16)
    assert_equal("\x00\x06hello!",s.to_s)
    s.len=10
    assert_equal("\x00\x0ahello!",s.to_s)
    s = IntString.new("hello!", Int16, :parse)
    s.len=10
    assert_equal("\x00\x0ahello!\x00\x00\x00\x00",s.to_s)
    s = IntString.new("hello!", Int16, :fix)
    s.len=10
    assert_equal("\x00\x06hello!",s.to_s)
  end

  def test_intstring_new
    assert_equal("\x06Hello!",IntString.new("Hello!").to_s)
    assert_equal("\x00\x06Hello!",IntString.new("Hello!",Int16).to_s)
    assert_equal("\x06\x00\x00\x00Hello!",IntString.new("Hello!",Int32le).to_s)
  end

  def test_intstring_read
    s = IntString.new
    s.read("\x06Hello!")
    assert_equal("Hello!", s.string)
    assert_equal("Hello!", s[:string])
    assert_equal(6, s.int.value)
    assert_equal(6, s.len)
  end

  def test_intstring_parse
    s = IntString.new
    s[:mode] = :parse
    s.parse("\x02Hello!")
    assert_equal("He", s.string)
    assert_equal(2, s.int.v)
    s.parse("\x0aHello!")
    assert_equal("Hello!\x00\x00\x00\x00", s.string)
    s[:mode] = :fix
    s.parse("\x0aHello!")
    assert_equal("Hello!", s.string)
  end

  def test_intstring_nocalc
    s = IntString.new
    s[:string] = "Hello"
    assert_equal(0,s.int.value)
  end

end

class IntTest < Test::Unit::TestCase
  include StructFu

  def test_int_to_s
    assert_equal("\x02",Int8.new(2).to_s) 
    assert_equal("\x00\x07",Int16.new(7).to_s) 
    assert_equal("\x00\x00\x00\x0a",Int32.new(10).to_s) 
  end

  def test_int_big
    assert_equal("\x00\x07",Int16be.new(7).to_s) 
    assert_equal("\x00\x00\x00\x0a",Int32be.new(10).to_s) 
  end

  def test_int_little
    assert_equal("\x07\x00",Int16le.new(7).to_s) 
    assert_equal("\x01\x04\x00\x00",Int32le.new(1025).to_s) 
  end

  def test_read
    assert_equal(7,Int16.new.read("\x00\x07").to_i) 
    assert_equal(Int32.new.read("\x00\x00\x00\x0a").to_i,10) 
    i = Int32.new
    i.read("\x00\x00\x00\xff")
    assert_equal(i.v, 255)
    assert_equal(7, Int16le.new.read("\x07\x00").to_i) 
    assert_equal(1025,Int32le.new.read("\x01\x04\x00\x00").to_i) 
    i = Int32le.new
    i.read("\xff\x00\x00\x00")
    assert_equal(i.v, 255)
  end

  def test_int_compare
    little = Int32le.new
    big = Int32be.new
    little.v = 128
    big.v = 0x80
    assert_not_equal(little.to_s, big.to_s)
    assert_equal(little.v, big.v)
    assert_equal(little[:value], big[:value])
    assert_equal(little.value, big.value)
  end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
