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

$:.unshift File.expand_path(File.dirname(__FILE__) + "/../lib")
require 'eventmachine'
require 'socket'
require 'test/unit'

class TestBasic < Test::Unit::TestCase

  def setup
    assert(!EM.reactor_running?)
  end

  def teardown
    assert(!EM.reactor_running?)
  end

  #-------------------------------------

  def test_libtype
    lt = EventMachine.library_type
    em_lib = (ENV["EVENTMACHINE_LIBRARY"] || $eventmachine_library || :xxx).to_sym

    # Running from test runner, under jruby.
    if RUBY_PLATFORM == 'java'
      unless em_lib == :pure_ruby
        assert_equal( :java, lt )
        return
      end
    end

    case em_lib
    when :pure_ruby
      assert_equal( :pure_ruby, lt )
    when :extension
      assert_equal( :extension, lt )
    when :java
      assert_equal( :java, lt )
    else
      # Running from jruby as a standalone test.
      if RUBY_PLATFORM == 'java'
        assert_equal( :java, lt )
      else
        assert_equal( :extension, lt )
      end
    end
  end

  #-------------------------------------


  def test_em
    EventMachine.run {
      EventMachine.add_timer 0 do
        EventMachine.stop
      end
    }
  end

  #-------------------------------------

  def test_timer
    n = 0
    EventMachine.run {
      EventMachine.add_periodic_timer(0.1) {
        n += 1
        EventMachine.stop if n == 2
      }
    }
  end

  #-------------------------------------

  # This test once threw an already-running exception.
  module Trivial
    def post_init
      EventMachine.stop
    end
  end

  def test_server
    EventMachine.run {
      EventMachine.start_server "localhost", 9000, Trivial
      EventMachine.connect "localhost", 9000
    }
    assert( true ) # make sure it halts
  end

  #--------------------------------------

  # EventMachine#run_block starts the reactor loop, runs the supplied block, and then STOPS
  # the loop automatically. Contrast with EventMachine#run, which keeps running the reactor
  # even after the supplied block completes.
  def test_run_block
    assert !EM.reactor_running?
    a = nil
    EM.run_block { a = "Worked" }
    assert a
    assert !EM.reactor_running?
  end


  #--------------------------------------

  # TODO! This is an unfinished edge case.
  # EM mishandles uncaught Ruby exceptions that fire from within #unbind handlers.
  # A uncaught Ruby exception results in a call to EM::release_machine (which is in an ensure
  # block in EM::run). But if EM is processing an unbind request, the release_machine call
  # will cause a segmentation fault.
  #

  TestHost = "127.0.0.1"
  TestPort = 9070

  class UnbindError < EM::Connection
    def initialize *args
      super
    end
    def connection_completed
      close_connection_after_writing
    end
    def unbind
      raise "Blooey"
    end
  end

  def xxx_test_unbind_error
    assert_raises( RuntimeError ) {
      EM.run {
        EM.start_server TestHost, TestPort
        EM.connect TestHost, TestPort, UnbindError
      }
    }
  end

  #------------------------------------
  #
  # TODO. This is an unfinished bug fix.
  # This case was originally reported by Dan Aquino. If you throw a Ruby exception
  # in a post_init handler, it gets rethrown as a confusing reactor exception.
  # The problem is in eventmachine.rb, which calls post_init within the private
  # initialize method of the EM::Connection class. This happens in both the EM::connect
  # method and in the code that responds to connection-accepted events.
  # What happens is that we instantiate the new connection object, which calls
  # initialize, and then after initialize returns, we stick the new connection object
  # into EM's @conns hashtable.
  # But the problem is that Connection::initialize calls #post_init before it returns,
  # and this may be user-written code that may throw an uncaught Ruby exception.
  # If that happens, the reactor will abort, and it will then try to run down open
  # connections. Because @conns never got a chance to properly reflect the new connection
  # (because initialize never returned), we throw a ConnectionNotBound error
  # (eventmachine.rb line 1080).
  # When the bug is fixed, activate this test case.
  #

  class PostInitError < EM::Connection
    def post_init
      aaa bbb # should produce a Ruby exception
    end
  end
  # This test causes issues, the machine becomes unreleasable after 
  # release_machine suffers an exception in event_callback.
  def xxx_test_post_init_error
    assert_raises( EventMachine::ConnectionNotBound ) {
      EM.run {
        EM::Timer.new(1) {EM.stop}
        EM.start_server TestHost, TestPort
        EM.connect TestHost, TestPort, PostInitError
      }
    }
    EM.run {
      EM.stop
    }
    assert !EM.reactor_running?
  end

  module BrsTestSrv
    def receive_data data
      $received << data
    end
    def unbind
      EM.stop
    end
  end
  module BrsTestCli
    def post_init
      send_data $sent
      close_connection_after_writing
    end
  end

  # From ticket #50
  def test_byte_range_send
    $received = ''
    $sent = (0..255).to_a.pack('C*')
    EM::run {
      EM::start_server TestHost, TestPort, BrsTestSrv
      EM::connect TestHost, TestPort, BrsTestCli

      EM::add_timer(0.5) { assert(false, 'test timed out'); EM.stop; Kernel.warn "test timed out!" }
    }
    assert_equal($sent, $received)
  end

  def test_bind_connect
    local_ip = UDPSocket.open {|s| s.connect('google.com', 80); s.addr.last }

    bind_port = rand(33333)+1025

    test = self
    EM.run do
      EM.start_server(TestHost, TestPort, Module.new do
        define_method :post_init do
          begin
            test.assert_equal bind_port, Socket.unpack_sockaddr_in(get_peername).first
            test.assert_equal local_ip, Socket.unpack_sockaddr_in(get_peername).last
          ensure
            EM.stop_event_loop
          end
        end
      end)
      EM.bind_connect local_ip, bind_port, TestHost, TestPort
    end
  end

  def test_reactor_thread?
    assert !EM.reactor_thread?
    EM.run { assert EM.reactor_thread?; EM.stop }
    assert !EM.reactor_thread?
  end

  def test_schedule_on_reactor_thread
    x = false
    EM.run do
      EM.schedule { x = true }
      EM.stop
    end
    assert x
  end
  
  def test_schedule_from_thread
    x = false
    assert !x
    EM.run do
      Thread.new { EM.schedule { x = true; EM.stop } }.join
    end
    assert x
  end

  def test_set_heartbeat_interval
    interval = 0.5
    EM.run {
      EM.set_heartbeat_interval interval
      $interval = EM.get_heartbeat_interval
      EM.stop
    }
    assert_equal(interval, $interval)
  end
end

