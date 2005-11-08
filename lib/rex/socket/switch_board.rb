require 'singleton'
require 'thread'
require 'rex'
require 'rex/socket'

module Rex
module Socket

###
#
# This class provides a global routing table that associates subnets with Comm
# classes.  Comm classes are used to instantiate objects that are tied to
# remote network entities.  For example, the Local Comm class is used to
# building network connections directly from the local machine whereas, for
# instance, a Meterpreter Comm would build a local socket pair that is
# associated with a connection established by a remote entity.  This can be
# seen as a uniform way of communicating with hosts through arbitrary
# channels.
#
###
class SwitchBoard

	include Singleton
	include Enumerable
	
	###
	#
	# This class represents a logical switch board route.
	#
	###
	class Route
		def initialize(subnet, netmask, comm)
			self.subnet      = subnet
			self.netmask     = netmask
			self.comm        = comm
			self.subnet_nbo  = Socket.resolv_nbo_i(subnet)
			self.netmask_nbo = Socket.resolv_nbo_i(netmask)
		end

		#
		# Sort according to bitmask
		#
		def <=>(other)
			self.bitmask <=> other.bitmask
		end

		#
		# Convert the netmask to a bitmask and cache it.
		#
		def bitmask
			@_bitmask = Socket.net2bitmask(self.netmask) if (@_bitmask == nil)
			@_bitmask
		end

		attr_reader :subnet, :netmask, :comm
		attr_reader :subnet_nbo, :netmask_nbo
	protected
		attr_writer :subnet, :netmask, :comm
		attr_writer :subnet_nbo, :netmask_nbo
	end

	##
	#
	# Class method wrappers
	#
	##

	def self.add_route(subnet, mask, comm)
		self.instance.add_route(subnet, mask, comm)
	end

	def self.remove_route(subnet, mask, comm)
		self.instance.remove_route(subnet, mask, comm)
	end

	def self.flush_routes
		self.instance.flush_routes
	end

	def self.each(&block)
		self.instance.each(&block)
	end

	def self.routes
		self.instance.routes
	end

	def self.best_comm(addr)
		self.instance.best_comm(addr)
	end

	def self.remove_by_comm(comm)
		self.instance.remove_by_comm(comm)
	end

	##
	#
	# Instance methods
	#
	##

	#
	# Adds a route for a given subnet and netmask destined through a given comm
	# instance.
	#
	def add_route(subnet, mask, comm)
		# If a bitmask was supplied, convert it.
		netmask = (mask.to_s =~ /^\d+$/) ? Rex::Socket.bit2netmask(mask.to_i) : mask
		rv      = true

		_init

		mutex.synchronize {
			# If the route already exists, return false to the caller.
			if (route_exists?(subnet, netmask) == false)
				self.routes << Route.new(subnet, netmask, comm)
			else
				rv = false
			end
		}

		rv
	end

	#
	# Removes a route for a given subnet and netmask destined through a given
	# comm instance.
	#
	def remove_route(subnet, mask, comm)
		# If a bitmask was supplied, convert it.
		netmask = (mask.to_s =~ /^\d+$/) ? Rex::Socket.bit2netmask(mask.to_i) : mask
		rv      = false

		_init

		mutex.synchronize {
			self.routes.delete_if { |route|
				if (route.subnet == subnet and route.netmask == netmask and route.comm == comm)
					rv = true
				else
					false
				end
			}
		}

		rv
	end

	#
	# Flushes all established routes.
	#
	def flush_routes
		_init

		self.routes = Array.new
	end

	#
	# Checks to see if a route already exists for the supplied subnet and
	# netmask.
	#
	def route_exists?(subnet, netmask)
		each { |route|
			return true if (route.subnet == subnet and route.netmask == netmask)
		}

		false
	end

	#
	# Enumerates each entry in the routing table.
	#
	def each(&block)
		_init

		routes.each(&block)
	end

	#
	# Finds the best possible comm for the supplied target address.
	#
	def best_comm(addr)
		addr_nbo = Socket.resolv_nbo_i(addr)
		comm     = nil
		msb      = 0

		each { |route|
			if ((route.subnet_nbo & route.netmask_nbo) ==
			    (addr_nbo & route.netmask_nbo))
				if (route.bitmask >= msb)
					comm = route.comm
					msb  = route.bitmask
				end		
			end
		}

		comm
	end

	#
	# Remove all routes that go through the supplied comm.
	#
	def remove_by_comm(comm)
		mutex.synchronize {
			routes.delete_if { |route|
				route.comm == comm
			}
		}
	end

	attr_reader :routes, :mutex

protected

	attr_writer :routes, :mutex

	def _init
		if (@_initialized != true)
			@_initialized = true
			self.routes   = Array.new
			self.mutex    = Mutex.new
		end
	end

end

end
end
