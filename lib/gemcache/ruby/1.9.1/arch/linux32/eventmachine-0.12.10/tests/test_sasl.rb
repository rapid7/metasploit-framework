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


class TestSASL < Test::Unit::TestCase

  # SASL authentication is usually done with UNIX-domain sockets, but
  # we'll use TCP so this test will work on Windows. As far as the
  # protocol handlers are concerned, there's no difference.

  Host,Port = "127.0.0.1",9560
  TestUser,TestPsw = "someone", "password"

  class SaslServer < EM::Connection
    include EM::Protocols::SASLauth
    def validate usr, psw, sys, realm
      usr == TestUser and psw == TestPsw
    end
  end

  class SaslClient < EM::Connection
    include EM::Protocols::SASLauthclient
  end

  def test_sasl
    resp = nil
    EM.run {
      EM.start_server( Host, Port, SaslServer )

      c = EM.connect( Host, Port, SaslClient )
      d = c.validate?( TestUser, TestPsw )
      d.timeout 2
      d.callback {
        resp = true
        EM.stop
      }
      d.errback {
        resp = false
        EM.stop
      }
    }
    assert_equal( true, resp )
  end

end
