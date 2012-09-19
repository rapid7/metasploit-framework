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
#

require 'eventmachine'
require 'test/unit'

class TestLineAndTextProtocol < Test::Unit::TestCase

  TestHost = "127.0.0.1"
  TestPort = 8905


  #--------------------------------------------------------------------

  class SimpleLineTest < EventMachine::Protocols::LineAndTextProtocol
    def receive_line line
      @line_buffer << line
    end
  end

  module StopClient
    def set_receive_data(&blk)
      @rdb = blk
    end
    
    def receive_data data
      @rdb.call(data) if @rdb
    end
    
    def unbind
      EM.add_timer(0.1) { EM.stop }
    end
  end


  def test_simple_lines
    lines_received = []
    EventMachine.run {
      EventMachine.start_server( TestHost, TestPort, SimpleLineTest ) do |conn|
        conn.instance_eval "@line_buffer = lines_received"
      end
      EventMachine.add_timer(4) {assert(false, "test timed out")}

      EventMachine.connect TestHost, TestPort, StopClient do |c|
        c.send_data "aaa\nbbb\r\nccc\n"
        c.close_connection_after_writing
      end
    }
    assert_equal( %w(aaa bbb ccc), lines_received )
  end

  #--------------------------------------------------------------------

  class SimpleLineTest < EventMachine::Protocols::LineAndTextProtocol
    def receive_error text
      @error_message << text
    end
  end

  def test_overlength_lines
    lines_received = []
    EventMachine.run {
      EventMachine.start_server( TestHost, TestPort, SimpleLineTest ) do |conn|
        conn.instance_eval "@error_message = lines_received"
      end
      EventMachine.add_timer(4) {assert(false, "test timed out")}

      EventMachine.connect TestHost, TestPort, StopClient do |c|
        c.send_data "a" * (16*1024 + 1)
        c.send_data "\n"
        c.close_connection_after_writing
      end

    }
    assert_equal( ["overlength line"], lines_received )
  end


  #--------------------------------------------------------------------

  class LineAndTextTest < EventMachine::Protocols::LineAndTextProtocol
    def post_init
    end
    def receive_line line
      if line =~ /content-length:\s*(\d+)/i
        @content_length = $1.to_i
      elsif line.length == 0
        set_binary_mode @content_length
      end
    end
    def receive_binary_data text
      send_data "received #{text.length} bytes"
      close_connection_after_writing
    end
  end

  def test_lines_and_text
    output = ''
    lines_received = []
    text_received = []
    EventMachine.run {
      EventMachine.start_server( TestHost, TestPort, LineAndTextTest ) do |conn|
        conn.instance_eval "@lines = lines_received; @text = text_received"
      end
      EventMachine.add_timer(4) {assert(false, "test timed out")}

      EventMachine.connect TestHost, TestPort, StopClient do |c|
        c.set_receive_data { |data| output << data }
        c.send_data "Content-length: 400\n"
        c.send_data "\n"
        c.send_data "A" * 400
        EM.add_timer(0.1) { c.close_connection_after_writing }
      end
    }
    assert_equal( "received 400 bytes", output )
  end

  #--------------------------------------------------------------------


  class BinaryTextTest < EventMachine::Protocols::LineAndTextProtocol
    def post_init
    end
    def receive_line line
      if line =~ /content-length:\s*(\d+)/i
        set_binary_mode $1.to_i
      else
        raise "protocol error"
      end
    end
    def receive_binary_data text
      send_data "received #{text.length} bytes"
      close_connection_after_writing
    end
  end

  def test_binary_text
    output = ''
    lines_received = []
    text_received = []
    EventMachine.run {
      EventMachine.start_server( TestHost, TestPort, BinaryTextTest ) do |conn|
        conn.instance_eval "@lines = lines_received; @text = text_received"
      end
      EventMachine.add_timer(4) {assert(false, "test timed out")}

      EventMachine.connect TestHost, TestPort, StopClient do |c|
        c.set_receive_data { |data| output << data }
        c.send_data "Content-length: 10000\n"
        c.send_data "A" * 10000
        EM.add_timer(0.2) { c.close_connection_after_writing }
      end
    }
    assert_equal( "received 10000 bytes", output )
  end

  #--------------------------------------------------------------------
end
