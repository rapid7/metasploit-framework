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

class TestSmtpClient < Test::Unit::TestCase

  Localhost = "127.0.0.1"
  Localport = 9801

  def setup
  end

  def teardown
  end

  def test_a
    # No real tests until we have a server implementation to test against.
    # This is what the call looks like, though:
    err = nil
    EM.run {
      d = EM::Protocols::SmtpClient.send :domain=>"example.com",
      :host=>Localhost,
      :port=>Localport, # optional, defaults 25
      :starttls=>true,
      :from=>"sender@example.com",
      :to=> ["to_1@example.com", "to_2@example.com"],
      :header=> {"Subject" => "This is a subject line"},
      :body=> "This is the body of the email",
      :verbose=>true
      d.errback {|e|
        err = e
        EM.stop
      }
    }
    assert(err)
  end

  def test_content
    err = nil
    EM.run {
      d = EM::Protocols::SmtpClient.send :domain=>"example.com",
      :host=>Localhost,
      :port=>Localport, # optional, defaults 25
      :starttls=>true,
      :from=>"sender@example.com",
      :to=> ["to_1@example.com", "to_2@example.com"],
      :content => ["Subject: xxx\r\n\r\ndata\r\n.\r\n"],
      :verbose=>true
      d.errback {|e|
        err = e
        EM.stop
      }
    }
    assert(err)
  end

end
