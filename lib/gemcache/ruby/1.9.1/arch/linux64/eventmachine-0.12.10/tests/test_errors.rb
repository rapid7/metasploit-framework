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


###### THIS TEST IS NOW OBSOLETE.
###### As of 27Dec07, the hookable error handling is obsolete because
###### of its performance impact.


$:.unshift "../lib"
require 'eventmachine'
require 'test/unit'

class TestErrors < Test::Unit::TestCase

  Localhost = "127.0.0.1"
  Localport = 9801

  def setup
  end

  def obsolete_teardown
    # Calling #set_runtime_error_hook with no block restores the
    # default handling of runtime_errors.
    #
    EM.set_runtime_error_hook
  end

  def test_no_tests_stub
  end

  # EM has a default handler for RuntimeErrors that are emitted from
  # user written code. You can override the handler if you wish, but it's
  # easier to call #set_runtime_error_hook.
  # Ordinarily, an error in user code invoked by the reactor aborts the
  # run.
  #
  def obsolete_test_unhandled_error
    assert_raises( RuntimeError ) {
      EM.run {
        EM.add_timer(0) {raise "AAA"}
      }
    }

  end

  def obsolete_test_handled_error
    err = nil
    EM.run {
      EM.set_runtime_error_hook {
        err = true
        EM.stop
      }
      EM.add_timer(0) {raise "AAA"}
    }
    assert err
  end
end

