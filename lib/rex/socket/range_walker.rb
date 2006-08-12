require 'rex/socket'

module Rex
module Socket

###
#
# This class provides an interface to enumerating an IP range
#
###
class RangeWalker

	#
	# Initializes a walker instance using the supplied range
	#
	def initialize(range, range_end=nil)
	
		a,b = range_end.nil? ? range.split('-') : [range, range_end]
		b ||= a
		
		a = Rex::Socket.addr_atoi(a)
		b = Rex::Socket.addr_atoi(b)
		
		if (b < a)		
			t = a
			a = b
			b = t
		end
		
		self.addr_start = a
		self.addr_stop  = b
		reset
	end

	#
	# Resets the subnet walker back to its original state.
	#
	def reset
		self.curr_ip     = self.addr_start
		self.num_ips     = self.addr_stop - self.addr_start + 1
	end

	#
	# Returns the next IP address.
	#
	def next_ip
		if (self.curr_ip > self.addr_stop)
			return nil
		end
		
		addr = Rex::Socket.addr_itoa(self.curr_ip)
		self.curr_ip += 1
		return addr
	end

	#
	# The total number of IPs within the range
	#
	attr_reader :num_ips

protected

	attr_writer   :num_ips # :nodoc:
	attr_accessor :addr_start, :addr_stop, :curr_ip # :nodoc:

end

end
end
