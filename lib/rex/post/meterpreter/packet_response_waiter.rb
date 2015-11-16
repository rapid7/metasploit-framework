# -*- coding: binary -*-

require 'timeout'
require 'thread'

module Rex
module Post
module Meterpreter

###
#
# This class handles waiting for a response to a given request
# and the subsequent response association.
#
###
class PacketResponseWaiter

  #
  # Initializes a response waiter instance for the supplied request
  # identifier.
  #
  def initialize(rid, completion_routine = nil, completion_param = nil)
    self.rid      = rid.dup
    self.response = nil

    if (completion_routine)
      self.completion_routine = completion_routine
      self.completion_param   = completion_param
    else
      self.mutex = Mutex.new
      self.cond  = ConditionVariable.new
    end
  end

  #
  # Checks to see if this waiter instance is waiting for the supplied
  # packet based on its request identifier.
  #
  def waiting_for?(packet)
    return (packet.rid == rid)
  end

  #
  # Notifies the waiter that the supplied response packet has arrived.
  #
  def notify(response)
    if (self.completion_routine)
      self.response = response
      self.completion_routine.call(response, self.completion_param)
    else
      self.mutex.synchronize do
        self.response = response
        self.cond.signal
      end
    end
  end

  #
  # Waits for a given time interval for the response packet to arrive.
  # If the interval is -1 we can wait forever.
  #
  def wait(interval)
    interval = nil if interval and interval == -1
    self.mutex.synchronize do
      if self.response.nil?
        self.cond.wait(self.mutex, interval)
      end
    end
    return self.response
  end

  attr_accessor :rid, :mutex, :cond, :response # :nodoc:
  attr_accessor :completion_routine, :completion_param # :nodoc:
end

end; end; end

