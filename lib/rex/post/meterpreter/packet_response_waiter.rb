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
      self.done  = false
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
    self.response = response

    if (self.completion_routine)
      self.completion_routine.call(response, self.completion_param)
    else
      self.done = true
    end
  end

  #
  # Waits for a given time interval for the response packet to arrive.
  # If the interval is -1 we can wait forever.
  #
  def wait(interval)
    if( interval and interval == -1 )
      while(not self.done)
        ::IO.select(nil, nil, nil, 0.1)
      end
    else
      begin
        Timeout.timeout(interval) {
          while(not self.done)
            ::IO.select(nil, nil, nil, 0.1)
          end
        }
      rescue Timeout::Error
        self.response = nil
      end
    end
    return self.response
  end

  attr_accessor :rid, :done, :response # :nodoc:
  attr_accessor :completion_routine, :completion_param # :nodoc:
end

end; end; end

