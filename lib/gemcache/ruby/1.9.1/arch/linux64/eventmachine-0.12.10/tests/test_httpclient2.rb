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

class TestHttpClient2 < Test::Unit::TestCase
  Localhost = "127.0.0.1"
  Localport = 9801

  def setup
  end

  def teardown
  end


  class TestServer < EM::Connection
  end

  # #connect returns an object which has made a connection to an HTTP server
  # and exposes methods for making HTTP requests on that connection.
  # #connect can take either a pair of parameters (a host and a port),
  # or a single parameter which is a Hash.
  #
  def test_connect
    EM.run {
      EM.start_server Localhost, Localport, TestServer
      http1 = EM::P::HttpClient2.connect Localhost, Localport
      http2 = EM::P::HttpClient2.connect( :host=>Localhost, :port=>Localport )
      EM.stop
    }
  end


  def test_bad_port
    EM.run {
      EM.start_server Localhost, Localport, TestServer
      assert_raises( ArgumentError ) {
        EM::P::HttpClient2.connect Localhost, "xxx"
      }
      EM.stop
    }
  end

  def test_bad_server
    err = nil
    EM.run {
      http = EM::P::HttpClient2.connect Localhost, 9999
      d = http.get "/"
      d.errback { err = true; d.internal_error; EM.stop }
    }
    assert(err)
  end

  def test_get
    content = nil
    EM.run {
      http = EM::P::HttpClient2.connect "google.com", 80
      d = http.get "/"
      d.callback {
        content = d.content
        EM.stop
      }
    }
    assert(content)
  end

  # Not a pipelined request because we wait for one response before we request the next.
  # XXX this test is broken because it sends the second request to the first connection
  # XXX right before the connection closes
  def _test_get_multiple
    content = nil
    EM.run {
      http = EM::P::HttpClient2.connect "google.com", 80
      d = http.get "/"
      d.callback {
        e = http.get "/"
        e.callback {
          content = e.content
          EM.stop
        }
      }
    }
    assert(content)
  end

  def test_get_pipeline
    headers, headers2 = nil, nil
    EM.run {
      http = EM::P::HttpClient2.connect "google.com", 80
      d = http.get("/")
      d.callback {
        headers = d.headers
      }
      e = http.get("/")
      e.callback {
        headers2 = e.headers
      }
      EM::Timer.new(1) {EM.stop}
    }
    assert(headers)
    assert(headers2)
  end


  def test_authheader
    EM.run {
      EM.start_server Localhost, Localport, TestServer
      http = EM::P::HttpClient2.connect Localhost, 18842
      d = http.get :url=>"/", :authorization=>"Basic xxx"
      d.callback {EM.stop}
      d.errback {EM.stop}
    }
  end

  def test_https_get
    d = nil
    EM.run {
      http = EM::P::HttpClient2.connect :host => 'www.amazon.com', :port => 443, :ssl => true
      d = http.get "/"
      d.callback {
        EM.stop
      }
    }
    assert_equal(200, d.status)
  end if EM.ssl?

end
