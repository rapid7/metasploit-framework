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

class TestPure < Test::Unit::TestCase


  Host,Port = "0.0.0.0", 9060


  # These tests are intended to exercise problems that come up in the
  # pure-Ruby implementation. However, we DON'T constrain them such that
  # they only run in pure-Ruby. These tests need to work identically in
  # any implementation.

  def setup
  end

  def teardown
  end

  #-------------------------------------

  # The EM reactor needs to run down open connections and release other resources
  # when it stops running. Make sure this happens even if user code throws a Ruby
  # exception.
  # One way to see this is to run identical tests that open a TCP server and throw
  # an exception. (We do this twice because an exception aborts a test. We make the
  # two tests identical except for the method name because we can't predict the order
  # in which the test harness will run them.)
  # If exception handling is incorrect, the second test will fail with a no-bind error
  # because the TCP server opened in the first test will not have been closed.
  #
  def run_exception
      EM.run {
        EM.start_server Host, Port
        raise "an exception"
      }
  end
  def test_exception_1
    assert_raises( RuntimeError ) { run_exception }
  end
  def test_exception_2
    ex_class = RUBY_PLATFORM == 'java' ? NativeException : RuntimeError
    assert_raises( ex_class ) { run_exception }
  end


  # Under some circumstances, the pure Ruby library would emit an Errno::ECONNREFUSED
  # exception on certain kinds of TCP connect-errors.
  # It's always been something of an open question whether EM should throw an exception
  # in these cases but the defined answer has always been to catch it the unbind method.
  # With a connect failure, the latter will always fire, but connection_completed will
  # never fire. So even though the point is arguable, it's incorrect for the pure Ruby
  # version to throw an exception.
  module TestConnrefused
    def unbind
      EM.stop
    end
    def connection_completed
      raise "should never get here"
    end
  end
  def test_connrefused
    EM.run {
      EM.connect "0.0.0.0", 60001, TestConnrefused
    }
  end


  # Make sure connection_completed gets called as expected with TCP clients. This is the
  # opposite of test_connrefused.
  # If the test fails, it will hang because EM.stop never gets called.
  #
  module TestConnaccepted
    def connection_completed
      EM.stop
    end
  end
  def test_connaccepted
    timeout = false
    EM.run {
      EM.start_server "0.0.0.0", 60002
      EM.connect "0.0.0.0", 60002, TestConnaccepted
      EM::Timer.new(1) {timeout = true; EM.stop}
    }
    assert_equal( false, timeout )
  end

  def test_reactor_running
    a = false
    EM.run {
      a = EM.reactor_running?
      EM.next_tick {EM.stop}
    }
    assert a
  end

end
