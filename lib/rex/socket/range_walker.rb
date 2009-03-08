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
			tmp = range.split('-')
			tmp[1] ||= tmp[0]
		
			if(tmp[0] == tmp[1] and tmp[0] =~ /\//)
				tmp = Rex::Socket.cidr_crack(tmp[0])
			end
		
			addr_a, addr_b = tmp
			addr_a, scope = tmp[0].split("%")
			addr_b, scope = tmp[1].split("%") if not scope

			addr_a = Rex::Socket.addr_atoi(addr_a)
			addr_b = Rex::Socket.addr_atoi(addr_b)

			if (addr_b < addr_a)		
				addr_t = addr_a
				addr_a = addr_b
				addr_b = addr_t
			end

			self.ranges << [addr_a,addr_b,scope]
		end
		
		reset
	end

	#
	# Resets the subnet walker back to its original state.
	#
	def reset
		self.curr_range  = 0
		self.curr_ip     = self.ranges[0][0]
		self.curr_scope  = self.ranges[0][2]
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
			self.curr_scope = self.ranges[self.curr_range][2]
		end
		
		addr = Rex::Socket.addr_itoa(self.curr_ip)
		self.curr_ip += 1
		
		addr << "%#{self.curr_scope}" if self.curr_scope

		return addr
	end

	#
	# The total number of IPs within the range
	#
	attr_reader :num_ips

protected

	attr_writer   :num_ips # :nodoc:
	attr_accessor :addr_start, :addr_stop, :curr_ip, :curr_range, :ranges, :curr_scope # :nodoc:

end

end
end
