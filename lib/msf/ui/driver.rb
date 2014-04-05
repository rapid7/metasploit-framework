# -*- coding: binary -*-
module Msf
module Ui

###
#
# The driver class is an abstract base class that is meant to provide
# a very general set of methods for 'driving' a user interface.
#
###
class Driver

  def initialize
  end

  #
  # Executes the user interface, optionally in an asynchronous fashion.
  #
  def run
    raise NotImplementedError
  end

  #
  # Stops executing the user interface.
  #
  def stop
  end

  #
  # Cleans up any resources associated with the UI driver.
  #
  def cleanup
  end

protected

end

end
end
