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

  # Arbitrary argument to {#completion_routine}
  #
  # @return [Object,nil]
  attr_accessor :completion_param

  # A callback to be called when this waiter is notified of a packet's
  # arrival. If not nil, this will be called with the response packet as first
  # parameter and {#completion_param} as the second.
  #
  # @return [Proc,nil]
  attr_accessor :completion_routine

  # @return [ConditionVariable]
  attr_accessor :cond

  # @return [Mutex]
  attr_accessor :mutex

  # @return [Packet]
  attr_accessor :response

  # @return [Integer] request ID to wait for
  attr_accessor :rid

  # @return [Boolean] indicates if part of the response has been received
  attr_accessor :in_progress

  #
  # Initializes a response waiter instance for the supplied request
  # identifier.
  #
  def initialize(rid, completion_routine = nil, completion_param = nil)
    self.rid      = rid.dup
    self.response = nil
    self.in_progress = false

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
  # @param response [Packet]
  # @return [void]
  def notify(response, in_progress = false)
    if (self.completion_routine)
      self.in_progress = in_progress
      unless in_progress
        self.response = response
        self.completion_routine.call(response, self.completion_param)
      end
    else
      self.mutex.synchronize do
        self.in_progress = in_progress
        unless in_progress
          # complete packet, ready for processing...
          self.response = response
          self.cond.signal
        end
      end
    end
  end

  #
  # Wait for a given time interval for the response packet to arrive.
  #
  # @param interval [Integer,nil] number of seconds to wait, or nil to wait
  #   forever
  # @return [Packet,nil] the response, or nil if the interval elapsed before
  #   receiving one
  def wait(interval)
    interval = nil if interval and interval == -1
    self.mutex.synchronize do
      if self.response.nil?
        loop do
          self.cond.wait(self.mutex, interval)
          break unless self.in_progress
          self.in_progress = false
        end
      end
    end
    return self.response
  end

end

end; end; end

