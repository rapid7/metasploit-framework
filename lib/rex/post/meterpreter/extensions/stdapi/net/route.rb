#!/usr/bin/env ruby

require 'ipaddr'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net

###
#
# Represents a logical network route.
#
###
class Route

	##
	#
	# Constructor
	#
	##

	#
	# Initializes a route instance.
	#
	def initialize(subnet, netmask, gateway)
		self.subnet  = IPAddr.ntop(subnet)
		self.netmask = IPAddr.ntop(netmask)
		self.gateway = IPAddr.ntop(gateway)
	end

	#
	# Provides a pretty version of the route.
	#
	def pretty
		return sprintf("%16s %16s %16s", subnet, netmask, gateway)
	end

	#
	# The subnet mask associated with the route.
	#
	attr_accessor :subnet
	#
	# The netmask of the subnet route.
	#
	attr_accessor :netmask
	#
	# The gateway to take for the subnet route.
	#
	attr_accessor :gateway

end

end; end; end; end; end; end