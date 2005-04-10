#!/usr/bin/ruby

require 'timeout'
require 'thread' 

module Rex
module Post
module Meterpreter

###
#
# PacketResponseWaiter
# --------------------
#
# This class handles waiting for a response to a given request
# and the subsequent response association
#
###
class PacketResponseWaiter
	def initialize(rid, completion_routine = nil, completion_param = nil)
		self.rid      = rid
		self.response = nil

		if (completion_routine)
			self.completion_routine = completion_routine
			self.completion_param   = completion_param
		else
			self.mutex = Mutex.new
			self.cond  = ConditionVariable.new
		end
	end

	def waiting_for?(packet)
		puts "comparing #{packet.rid} (#{packet.rid.length}) to #{rid} (#{rid.length})"
		return (packet.rid == rid)
	end

	def notify(response)
		self.response = response

		if (self.completion_routine)
			self.completion_routine(self.completion_param, response)
		else
			self.mutex.synchronize {
				self.cond.signal
			}
		end
	end

	def wait(interval)
		begin
			timeout(interval) { 
				self.mutex.synchronize { 
					self.cond.wait(self.mutex) 
				} 
			}
		rescue TimeoutError
			self.response = nil
		end

		return self.response
	end

	attr_accessor :rid, :mutex, :cond, :response
	attr_accessor :completion_routine, :completion_param
end

end; end; end
