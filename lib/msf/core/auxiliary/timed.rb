# -*- coding: binary -*-
module Msf

###
#
# This module provides methods for time-limited modules
#
###

module Auxiliary::Timed

require 'timeout'

#
# Initializes an instance of a timed module
#
def initialize(info = {})
  super

  register_options(
    [
      OptInt.new('RUNTIME', [ true, "The number of seconds to run the test", 5 ] )
    ], Auxiliary::Timed)

end

#
# The command handler when launched from the console
#
def run
  secs = datastore['RUNTIME'].to_i
  print_status("Running module for #{secs} seconds...")
  begin
    Timeout.timeout(secs) {	self.run_timed }
  rescue Timeout::Error
  end
end

end
end

