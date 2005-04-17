#!/usr/bin/ruby

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
		self.subnet  = convert_to_string(subnet)
		self.netmask = convert_to_string(netmask)
		self.gateway = convert_to_string(gateway)
	end

	# Provides a pretty version of the route
	def pretty
		return sprintf("%16s %16s %16s", subnet, netmask, gateway)
	end

	attr_accessor :subnet, :netmask, :gateway

protected

	# Converts the raw network-byte order IP address into a string
	def convert_to_string(raw)
		return sprintf("%d.%d.%d.%d", raw[0], raw[1], raw[2], raw[3])
	end

end

end; end; end; end; end; end
