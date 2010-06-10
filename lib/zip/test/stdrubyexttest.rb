#!/usr/bin/env ruby

$VERBOSE = true

$: << "../lib"

require 'test/unit'
require 'zip/stdrubyext'

class ModuleTest < Test::Unit::TestCase

  def test_select_map
    assert_equal([2, 4, 8, 10], [1, 2, 3, 4, 5].select_map { |e| e == 3 ? nil : 2*e })
  end
  
end

class StringExtensionsTest < Test::Unit::TestCase

  def test_starts_with
    assert("hello".starts_with(""))
    assert("hello".starts_with("h"))
    assert("hello".starts_with("he"))
    assert(! "hello".starts_with("hello there"))
    assert(! "hello".starts_with(" he"))

    assert_raise(TypeError, "type mismatch: NilClass given") { 
      "hello".starts_with(nil) 
    }
  end

  def test_ends_with
    assert("hello".ends_with("o"))
    assert("hello".ends_with("lo"))
    assert("hello".ends_with("hello"))
    assert(!"howdy".ends_with("o"))
    assert(!"howdy".ends_with("oy"))
    assert(!"howdy".ends_with("howdy doody"))
    assert(!"howdy".ends_with("doody howdy"))
  end

  def test_ensure_end
    assert_equal("hello!", "hello!".ensure_end("!"))
    assert_equal("hello!", "hello!".ensure_end("o!"))
    assert_equal("hello!", "hello".ensure_end("!"))
    assert_equal("hello!", "hel".ensure_end("lo!"))
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
