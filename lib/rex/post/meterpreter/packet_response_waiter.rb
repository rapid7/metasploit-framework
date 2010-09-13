#!/usr/bin/env ruby

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
			self.done    = false
			self.wthread = initialize_waiter_thread
		end
	end

	#
	# Create an idle thread we can wait on
	#
	def initialize_waiter_thread
		::Thread.new do
			while (! self.done)
				::IO.select(nil,nil,nil,5.0)
			end
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
			self.wthread.kill
		end
	end

	#
	# Waits for a given time interval for the response packet to arrive.
	# If the interval is -1 we can wait forever.
	#
	def wait(interval)
		if( interval and interval == -1 )
			self.wthread.join
		else
			begin
				Timeout.timeout(interval) { self.wthread.join }
			rescue Timeout::Error
				self.response = nil
			end
		end
		return self.response
	end

	attr_accessor :rid, :done, :response, :wthread # :nodoc:
	attr_accessor :completion_routine, :completion_param # :nodoc:
end

end; end; end

