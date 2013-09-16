# -*- coding: binary -*-
require 'thread'

module Rex
module Sync

###
#
# This class wraps the logical ConditionVariable class to make it an easier to
# work with interface that is similar to Windows' synchronization events.
#
###
class Event

  Infinite = 10000

  #
  # Initializes a waitable event.  The state parameter initializes the
  # default state of the event.  If auto_reset is true, any calls to set()
  # will automatically reset the event back to an unset state.
  #
  def initialize(state = false, auto_reset = true, param = nil)
    self.state      = state
    self.auto_reset = auto_reset
    self.param      = param
    self.mutex      = Mutex.new
    self.cond       = ConditionVariable.new
  end

  #
  # Sets the event and wakes up anyone who was waiting.
  #
  def set(param = nil)
    self.param = param

    self.mutex.synchronize {
      # If this event does not automatically reset its state,
      # set the state to true
      if (auto_reset == false)
        self.state = true
      end

      self.cond.broadcast
    }
  end

  #
  # Resets the signaled state to false.
  #
  def reset
    self.param = nil
    self.state = false
  end

  #
  # Alias notify with set.
  #
  alias notify set

  #
  # Waits for the event to become signaled.  Timeout is measured in
  # seconds.  Raises TimeoutError if the condition does not become signaled.
  #

  begin
    # XXX: we need to replace this code
    #      continuations slow down YARV
    require "continuation" if not defined? callcc
  rescue ::LoadError
  end

  def wait(t = Infinite)
    callcc { |ctx|
      self.mutex.synchronize {
        ctx.call if (self.state == true)

        Timeout.timeout(t) {
          self.cond.wait(self.mutex)
        }
      }
    }

    return self.param
  end

protected

  attr_accessor :state, :auto_reset # :nodoc:
  attr_accessor :param, :mutex, :cond # :nodoc:

end

end
end

