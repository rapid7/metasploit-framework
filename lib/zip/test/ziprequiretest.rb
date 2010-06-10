#!/usr/bin/env ruby

$VERBOSE = true

$: << "../lib"

require 'test/unit'
require 'zip/ziprequire'

$: << 'data/rubycode.zip' << 'data/rubycode2.zip'

class ZipRequireTest < Test::Unit::TestCase
  def test_require
    assert(require('data/notzippedruby'))
    assert(!require('data/notzippedruby'))

    assert(require('zippedruby1'))
    assert(!require('zippedruby1'))

    assert(require('zippedruby2'))
    assert(!require('zippedruby2'))

    assert(require('zippedruby3'))
    assert(!require('zippedruby3'))

    c1 = NotZippedRuby.new
    assert(c1.returnTrue)
    assert(ZippedRuby1.returnTrue)
    assert(!ZippedRuby2.returnFalse)
    assert_equal(4, ZippedRuby3.multiplyValues(2, 2))
  end

  def test_get_resource
    get_resource("aResource.txt") {
      |f|
      assert_equal("Nothing exciting in this file!", f.read)
    }
  end
end

# Copyright (C) 2002 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
