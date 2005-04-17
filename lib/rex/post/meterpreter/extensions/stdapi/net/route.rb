#!/usr/bin/ruby

require 'ipaddr'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net

###
#
# Route
# -----
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
	
	def initialize(subnet, netmask, gateway)
		self.subnet  = IPAddr.ntop(subnet)
		self.netmask = IPAddr.ntop(netmask)
		self.gateway = IPAddr.ntop(gateway)
	end

	# Provides a pretty version of the route
	def pretty
		return sprintf("%16s %16s %16s", subnet, netmask, gateway)
	end

	attr_accessor :subnet, :netmask, :gateway

end

end; end; end; end; end; end
