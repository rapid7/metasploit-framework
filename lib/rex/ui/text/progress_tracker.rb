# -*- coding: binary -*-
require 'rex/ui/progress_tracker'

module Rex
module Ui
module Text

###
#
# This module implements progress tracking against a text interface.
#
###
class ProgressTracker < Rex::Ui::ProgressTracker

  def initialize(output)
    self.output = output
    self.start  = 0
    self.stop   = 0
    self.pos    = 0
  end

  #
  # Passes a generic status message that isn't necessarily associated
  # with a step event.
  #
  def status(msg = '')
    output.print_status(msg)
  end

  #
  # Updates the status associated with the current step.
  #
  def step_status(msg = '')
    output.print_status("#{pos}: #{msg}") if (msg and msg.length > 0)
  end

  #
  # An error occurred that may result in aborting the progress.
  #
  def error(msg = '')
    output.print_error(msg)
  end

  #
  # Progress has been aborted, the reason is supplied in msg.
  #
  def abort(msg = '')
    output.print_error("fatal: #{msg}")
  end

  attr_accessor :output

end

end
end
end
