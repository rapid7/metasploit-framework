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

class TestSmtpServer < Test::Unit::TestCase

  # Don't test on port 25. It requires superuser and there's probably
  # a mail server already running there anyway.
  Localhost = "127.0.0.1"
  Localport = 25001

  # This class is an example of what you need to write in order
  # to implement a mail server. You override the methods you are
  # interested in. Some, but not all, of these are illustrated here.
  #
  class Mailserver < EM::Protocols::SmtpServer

    attr_reader :my_msg_body, :my_sender, :my_recipients

    def initialize *args
      super
    end
    def receive_sender sender
      @my_sender = sender
      #p sender
      true
    end
    def receive_recipient rcpt
      @my_recipients ||= []
      @my_recipients << rcpt
      true
    end
    def receive_data_chunk c
      @my_msg_body = c.last
    end
    def connection_ended
      EM.stop
    end
  end

  def test_mail
    c = nil
    EM.run {
      EM.start_server( Localhost, Localport, Mailserver ) {|conn| c = conn}
      EM::Timer.new(2) {EM.stop} # prevent hanging the test suite in case of error
      EM::Protocols::SmtpClient.send :host=>Localhost,
        :port=>Localport,
        :domain=>"bogus",
        :from=>"me@example.com",
        :to=>"you@example.com",
        :header=> {"Subject"=>"Email subject line", "Reply-to"=>"me@example.com"},
        :body=>"Not much of interest here."

    }
    assert_equal( "Not much of interest here.", c.my_msg_body )
    assert_equal( "<me@example.com>", c.my_sender )
    assert_equal( ["<you@example.com>"], c.my_recipients )
  end
end
