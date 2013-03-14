# $Id$
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 8 April 2006
# 
# See EventMachine and EventMachine::Connection for documentation and
# usage examples.
#
#----------------------------------------------------------------------------
#
# Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
# Gmail: blackhedd
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of either: 1) the GNU General Public License
# as published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version; or 2) Ruby's License.
# 
# See the file COPYING for complete licensing information.
#
#---------------------------------------------------------------------------
#
#
#

$:.unshift "../lib"
require 'eventmachine'
require 'test/unit'

class TestFutures < Test::Unit::TestCase

  def setup
  end

  def teardown
  end

  def test_future
      assert_equal(100, EventMachine::Deferrable.future(100) )

      p1 = proc { 100 + 1 }
      assert_equal(101, EventMachine::Deferrable.future(p1) )
  end

  class MyFuture
      include EventMachine::Deferrable
      def initialize *args
        super
        set_deferred_status :succeeded, 40
      end
  end

  class MyErrorFuture
      include EventMachine::Deferrable
      def initialize *args
        super
        set_deferred_status :failed, 41
      end
  end


  def test_future_1
      # Call future with one additional argument and it will be treated as a callback.
      def my_future
        MyFuture.new
      end

      value = nil
      EventMachine::Deferrable.future my_future, proc {|v| value=v}
      assert_equal( 40, value )
  end


  def test_future_2
      # Call future with two additional arguments and they will be treated as a callback
      # and an errback.
      value = nil
      EventMachine::Deferrable.future MyErrorFuture.new, nil, proc {|v| value=v}
      assert_equal( 41, value )
  end


  def test_future_3
      # Call future with no additional arguments but with a block, and the block will be
      # treated as a callback.
      value = nil
      EventMachine::Deferrable.future MyFuture.new do |v|
        value=v
      end
      assert_equal( 40, value )
  end


  class RecursiveCallback
      include EventMachine::Deferrable
  end

  # A Deferrable callback can call #set_deferred_status to change the values
  # passed to subsequent callbacks.
  #
  def test_recursive_callbacks
      n = 0 # counter assures that all the tests actually run.
      rc = RecursiveCallback.new
      rc.callback {|a|
        assert_equal(100, a)
        n += 1
        rc.set_deferred_status :succeeded, 101, 101
      }
      rc.callback {|a,b|
        assert_equal(101, a)
        assert_equal(101, b)
        n += 1
        rc.set_deferred_status :succeeded, 102, 102, 102
      }
      rc.callback {|a,b,c|
        assert_equal(102, a)
        assert_equal(102, b)
        assert_equal(102, c)
        n += 1
      }
      rc.set_deferred_status :succeeded, 100
      assert_equal(3, n)
  end

  def test_syntactic_sugar
    rc = RecursiveCallback.new
    rc.set_deferred_success 100
    rc.set_deferred_failure 200
  end

  # It doesn't raise an error to set deferred status more than once.
  # In fact, this is a desired and useful idiom when it happens INSIDE
  # a callback or errback.
  # However, it's less useful otherwise, and in fact would generally be
  # indicative of a programming error. However, we would like to be resistant
  # to such errors. So whenever we set deferred status, we also clear BOTH
  # stacks of handlers.
  #
  def test_double_calls
    s = 0
    e = 0

    d = EM::DefaultDeferrable.new
    d.callback {s += 1}
    d.errback {e += 1}

    d.succeed	# We expect the callback to be called, and the errback to be DISCARDED.
    d.fail	  # Presumably an error. We expect the errback NOT to be called.
    d.succeed	# We expect the callback to have been discarded and NOT to be called again.

    assert_equal(1, s)
    assert_equal(0, e)
  end

  # Adding a callback to a Deferrable that is already in a success state executes the callback
  # immediately. The same applies to a an errback added to an already-failed Deferrable.
  # HOWEVER, we expect NOT to be able to add errbacks to succeeded Deferrables, or callbacks
  # to failed ones.
  #
  # We illustrate this with a rather contrived test. The test calls #fail after #succeed,
  # which ordinarily would not happen in a real program.
  #
  # What we're NOT attempting to specify is what happens if a Deferrable is succeeded and then
  # failed (or vice-versa). Should we then be able to add callbacks/errbacks of the appropriate
  # type for immediate execution? For now at least, the official answer is "don't do that."
  #
  def test_delayed_callbacks
    s1 = 0
    s2 = 0
    e = 0

    d = EM::DefaultDeferrable.new
    d.callback {s1 += 1}

    d.succeed # Triggers and discards the callback.

    d.callback {s2 += 1} # This callback is executed immediately and discarded.

    d.errback {e += 1} # This errback should be DISCARDED and never execute.
    d.fail # To prove it, fail and assert e is 0

    assert_equal( [1,1], [s1,s2] )
    assert_equal( 0, e )
  end

  def test_timeout
    n = 0
    EM.run {
      d = EM::DefaultDeferrable.new
      d.callback {n = 1; EM.stop}
      d.errback {n = 2; EM.stop}
      d.timeout(1)
    }
    assert_equal( 2, n )
  end

end
