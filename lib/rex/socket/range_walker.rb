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
	def initialize(ranges)
	
		self.ranges = []
		
		ranges.split(',').each do |range|
			a,b = range.split('-')
			b ||= a

			a = Rex::Socket.addr_atoi(a)
			b = Rex::Socket.addr_atoi(b)

			if (b < a)		
				t = a
				a = b
				b = t
			end
		
			self.ranges << [a,b]
		end
		
		reset
	end

	#
	# Resets the subnet walker back to its original state.
	#
	def reset
		self.curr_range  = 0
		self.curr_ip     = self.ranges[0][0]
		self.num_ips     = 0
		self.ranges.each {|r| self.num_ips += r[1]-r[0] + 1 }
	end

	#
	# Returns the next IP address.
	#
	def next_ip
		if (self.curr_ip > self.ranges[self.curr_range][1])
			if (self.curr_range == self.ranges.length - 1)
				return nil
			end
			self.curr_range += 1
			self.curr_ip = self.ranges[self.curr_range][0]
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
	attr_accessor :addr_start, :addr_stop, :curr_ip, :curr_range, :ranges # :nodoc:

end

end
end
