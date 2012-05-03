#!/usr/bin/env ruby

#--
# Portions copyright 2004 by Jim Weirich (jim@weirichhouse.org).
# Portions copyright 2005 by Sam Ruby (rubys@intertwingly.net).
# All rights reserved.

# Permission is granted for use, copying, modification, distribution,
# and distribution of modified versions of this work as long as the
# above copyright notice is included.
#++

require 'test/unit'
require 'test/preload'
require 'builder'
require 'builder/css'

class TestCSS < Test::Unit::TestCase
  def setup
    @css = Builder::CSS.new
  end

  def test_create
    assert_not_nil @css
  end

  def test_no_block
    @css.body
    assert_equal 'body', @css.target!
  end

  def test_block
    @css.body {
      color 'green'
    }
    assert_equal "body {\n  color: green;\n}\n\n", @css.target!
  end
    
  def test_id
    @css.id!('nav') { color 'green' }
    assert_equal "#nav {\n  color: green;\n}\n\n", @css.target!
  end

  def test_class
    @css.class!('nav') { color 'green' }
    assert_equal ".nav {\n  color: green;\n}\n\n", @css.target!
  end

  def test_elem_with_id
    @css.div(:id => 'nav') { color 'green' }
    assert_equal "div#nav {\n  color: green;\n}\n\n", @css.target!
  end

  def test_elem_with_class
    @css.div(:class => 'nav') { color 'green' }
    assert_equal "div.nav {\n  color: green;\n}\n\n", @css.target!
  end

  def test_comment
    @css.comment!('foo')
    assert_equal "/* foo */\n", @css.target!
  end

  def test_selector
    @css.a(:hover) { color 'green' }
    assert_equal "a:hover {\n  color: green;\n}\n\n", @css.target!
  end

  def test_plus
    @css.h1 + @css.span
    assert_equal "h1 + span", @css.target!
  end

  def test_plus_with_block
    @css.h1 + @css.span { color 'green' }
    assert_equal "h1 + span {\n  color: green;\n}\n\n", @css.target!
  end

  def test_contextual
    @css.h1 >> @css.span
    assert_equal "h1  span", @css.target!
  end

  def test_contextual_with_block
    @css.h1 >> @css.span { color 'green' }
    assert_equal "h1  span {\n  color: green;\n}\n\n", @css.target!
  end

  def test_child
    @css.h1 > @css.span
    assert_equal "h1 > span", @css.target!
  end

  def test_child_with_block
    @css.h1 > @css.span { color 'green' }
    assert_equal "h1 > span {\n  color: green;\n}\n\n", @css.target!
  end

  def test_multiple_op
    @css.h1 + @css.span + @css.span
    assert_equal "h1 + span + span", @css.target!
  end

  def test_all
    @css.h1 | @css.h2 { color 'green' }
    assert_equal "h1 , h2 {\n  color: green;\n}\n\n", @css.target!
  end

  def test_all_with_atts
    @css.h1(:class => 'foo') | @css.h2(:class => 'bar') { color 'green' }
    assert_equal "h1.foo , h2.bar {\n  color: green;\n}\n\n", @css.target!
  end

  def test_multiple_basic
    @css.body { color 'green' }
    @css.h1   { color 'green' }
    assert_equal "body {\n  color: green;\n}\n\nh1 {\n  color: green;\n}\n\n", @css.target!
  end

  def test_multiple_ops
    @css.body { color 'green' }
    @css.body > @css.h1 { color 'green' }
    assert_equal "body {\n  color: green;\n}\n\nbody > h1 {\n  color: green;\n}\n\n", @css.target!
  end
end
