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

$:.unshift "../lib"
require 'eventmachine'
require 'test/unit'

class TestSomeExceptions < Test::Unit::TestCase

  # Read the commentary in EventMachine#run.
  # This test exercises the ensure block in #run that makes sure
  # EventMachine#release_machine gets called even if an exception is
  # thrown within the user code. Without the ensured call to release_machine,
  # the second call to EventMachine#run will fail with a C++ exception
  # because the machine wasn't cleaned up properly.

  def test_a
    assert_raises(RuntimeError) {
      EventMachine.run {
      raise "some exception"
    }
    }
  end

  def test_b
    assert_raises(RuntimeError) {
      EventMachine.run {
      raise "some exception"
    }
    }
  end

end
