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

class TestKeyboardEvents < Test::Unit::TestCase

  def setup
  end

  def teardown
  end

  module KbHandler
    include EM::Protocols::LineText2
    def receive_line d
      EM::stop if d == "STOP"
    end
  end

  # This test doesn't actually do anything useful but is here to
  # illustrate the usage. If you removed the timer and ran this test
  # by itself on a console, and then typed into the console, it would
  # work.
  # I don't know how to get the test harness to simulate actual keystrokes.
  # When someone figures that out, then we can make this a real test.
  #
  def test_kb
    EM.run {
      EM.open_keyboard KbHandler
      EM::Timer.new(1) { EM.stop }
    } if $stdout.tty? # don't run the test unless it stands a chance of validity.
  end

end
