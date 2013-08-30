# -*- coding: binary -*-
module Rex
module Ui

###
#
# This module tracks the progress of an arbitrary task in a generic fashion.
# The actual implementation is left up to the thing that derives from this
# module.
#
###
class ProgressTracker

  require 'rex/ui/text/progress_tracker'

  def initialize
    self.start = 0
    self.stop  = 0
    self.pos   = 0
  end

  #
  # Sets start and step using a range.
  #
  def range=(rng)
    self.start = rng.begin
    self.stop  = rng.end
  end

  #
  # Sets the start and resets the position.
  #
  def start=(start)
    @start   = start
    self.pos = start
  end

  #
  # Steps with a given message and step size.
  #
  def step(status = nil, n = 1)
    self.pos += n if (self.pos + n <= self.stop)

    step_status(status)

    self.pos
  end

  #
  # Resets the current step location.
  #
  def reset(n = self.start)
    self.pos = n
  end

  #
  # Passes a generic status message that isn't necessarily associated
  # with a step event.
  #
  def status(msg = nil)
  end

  #
  # Updates the status associated with the current step.
  #
  def step_status(msg = nil)
  end

  #
  # An error occurred that may result in aborting the progress.
  #
  def error(msg = nil)
  end

  #
  # Progress has been aborted, the reason is supplied in msg.
  #
  def abort(msg = nil)
  end

  #
  # The start of the progress.
  #
  attr_reader   :start
  #
  # The last position in the progress.
  #
  attr_accessor :stop
  #
  # The current position in the progress.
  #
  attr_accessor :pos

end

end
end
