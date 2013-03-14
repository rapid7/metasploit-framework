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
require 'socket'
require 'test/unit'

class TestServers < Test::Unit::TestCase

  Host = "127.0.0.1"
  Port = 9555

  module NetstatHelper
    GlobalUdp4Rexp = /udp.*\s+(?:\*|(?:0\.){3}0)[:.](\d+)\s/i
    GlobalTcp4Rexp = /tcp.*\s+(?:\*|(?:0\.){3}0)[:.](\d+)\s/i
    LocalUdpRexp = /udp.*\s+(?:127\.0\.0\.1|::1)[:.](\d+)\s/i
    LocalTcpRexp = /tcp.*\s+(?:127\.0\.0\.1|::1)[:.](\d+)\s/i
    def grep_netstat(pattern)
      `netstat -an`.scan(/^.*$/).grep(pattern)
    end
  end
  include NetstatHelper

  class TestStopServer < EM::Connection
    def initialize *args
      super
    end
    def post_init
      # TODO,sucks that this isn't OOPy enough.
      EM.stop_server @server_instance
    end
  end

  def run_test_stop_server
    EM.run {
      sig = EM.start_server(Host, Port)
      assert(grep_netstat(LocalTcpRexp).grep(%r(#{Port})).size >= 1, "Server didn't start")
      EM.stop_server sig
      # Give the server some time to shutdown.
      EM.add_timer(0.1) {
        assert(grep_netstat(LocalTcpRexp).grep(%r(#{Port})).empty?, "Servers didn't stop")
        EM.stop
      }
    }
  end
  def test_stop_server
    assert(grep_netstat(LocalTcpRexp).grep(Port).empty?, "Port already in use")
    5.times {run_test_stop_server}
    assert(grep_netstat(LocalTcpRexp).grep(%r(#{Port})).empty?, "Servers didn't stop")
  end

end
