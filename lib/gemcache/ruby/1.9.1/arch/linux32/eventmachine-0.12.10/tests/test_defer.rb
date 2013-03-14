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

class TestDeferUsage < Test::Unit::TestCase

  def test_defers
    n = 0
    n_times = 20
    EM.run {
      n_times.times {
        work_proc = proc { n += 1 }
        callback = proc { EM.stop if n == n_times }
        EM.defer work_proc, callback
      }
    }
    assert_equal( n, n_times )
  end unless RUBY_VERSION >= '1.9.0'

end

