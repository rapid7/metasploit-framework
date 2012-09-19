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

class TestHttpClient < Test::Unit::TestCase

    Localhost = "127.0.0.1"
    Localport = 9801

  def setup
  end

  def teardown
  end

  #-------------------------------------

  def test_http_client
    ok = false
    EventMachine.run {
      c = EventMachine::Protocols::HttpClient.send :request, :host => "www.bayshorenetworks.com", :port => 80
      c.callback {
        ok = true
        EventMachine.stop
      }
      c.errback {EventMachine.stop} # necessary, otherwise a failure blocks the test suite forever.
    }
    assert ok
  end

  #-------------------------------------

  def test_http_client_1
    ok = false
    EventMachine.run {
      c = EventMachine::Protocols::HttpClient.send :request, :host => "www.bayshorenetworks.com", :port => 80
      c.callback {ok = true; EventMachine.stop}
      c.errback {EventMachine.stop}
    }
    assert ok
  end

  #-------------------------------------

  def test_http_client_2
    ok = false
    EventMachine.run {
      c = EventMachine::Protocols::HttpClient.send :request, :host => "www.bayshorenetworks.com", :port => 80
      c.callback {|result|
        ok = true;
        EventMachine.stop
      }
      c.errback {EventMachine.stop}
    }
    assert ok
  end


  #-----------------------------------------

  # Test a server that returns a page with a zero content-length.
  # This caused an early version of the HTTP client not to generate a response,
  # causing this test to hang. Observe, there was no problem with responses
  # lacking a content-length, just when the content-length was zero.
  #
  class EmptyContent < EventMachine::Connection
      def initialize *args
        super
      end
      def receive_data data
        send_data "HTTP/1.0 404 ...\r\nContent-length: 0\r\n\r\n"
        close_connection_after_writing
      end
  end

  def test_http_empty_content
      ok = false
      EventMachine.run {
        EventMachine.start_server "127.0.0.1", 9701, EmptyContent
        c = EventMachine::Protocols::HttpClient.send :request, :host => "127.0.0.1", :port => 9701
        c.callback {|result|
          ok = true
          EventMachine.stop
        }
      }
      assert ok
  end


  #---------------------------------------

  class PostContent < EventMachine::Protocols::LineAndTextProtocol
      def initialize *args
        super
        @lines = []
      end
      def receive_line line
        if line.length > 0
          @lines << line
        else
          process_headers
        end
      end
      def receive_binary_data data
        @post_content = data
        send_response
      end
      def process_headers
        if @lines.first =~ /\APOST ([^\s]+) HTTP\/1.1\Z/
          @uri = $1.dup
        else
          raise "bad request"
        end

        @lines.each {|line|
          if line =~ /\AContent-length:\s*(\d+)\Z/i
            @content_length = $1.dup.to_i
          elsif line =~ /\AContent-type:\s*(\d+)\Z/i
            @content_type = $1.dup
          end
        }

        raise "invalid content length" unless @content_length
        set_binary_mode @content_length
      end
      def send_response
        send_data "HTTP/1.1 200 ...\r\nConnection: close\r\nContent-length: 10\r\nContent-type: text/html\r\n\r\n0123456789"
        close_connection_after_writing
      end
  end

  # TODO, this is WRONG. The handler is asserting an HTTP 1.1 request, but the client
  # is sending a 1.0 request. Gotta fix the client
  def test_post
      response = nil
      EventMachine.run {
        EventMachine.start_server Localhost, Localport, PostContent
        EventMachine.add_timer(2) {raise "timed out"}
        c = EventMachine::Protocols::HttpClient.request(
          :host=>Localhost,
          :port=>Localport,
          :method=>:post,
          :request=>"/aaa",
          :content=>"XYZ",
          :content_type=>"text/plain"
        )
        c.callback {|r|
          response = r
          EventMachine.stop
        }
      }

      assert_equal( 200, response[:status] )
      assert_equal( "0123456789", response[:content] )
  end


  # TODO, need a more intelligent cookie tester.
  # In fact, this whole test-harness needs a beefier server implementation.
  def test_cookie
    ok = false
    EM.run {
      c = EM::Protocols::HttpClient.send :request, :host => "www.bayshorenetworks.com", :port => 80, :cookie=>"aaa=bbb"
      c.callback {|result|
        ok = true;
        EventMachine.stop
      }
      c.errback {EventMachine.stop}
    }
    assert ok
  end

  # We can tell the client to send an HTTP/1.0 request (default is 1.1).
  # This is useful for suppressing chunked responses until those are working.
  def test_version_1_0
    ok = false
    EM.run {
      c = EM::P::HttpClient.request(
        :host => "www.bayshorenetworks.com",
        :port => 80,
        :version => "1.0"
      )
      c.callback {|result|
        ok = true;
        EventMachine.stop
      }
      c.errback {EventMachine.stop}
    }
    assert ok
  end

end
