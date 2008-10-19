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
# This class represents a logical physical interface
# on the remote machine.
#
###
class Interface

	##
	#
	# Constructor
	#
	##

	#
	# Returns a logical interface and initializes it to the supplied
	# parameters.
	#
	def initialize(ip, netmask, mac_addr, mac_name)
		self.ip       = IPAddr.ntop(ip)
		self.netmask  = IPAddr.ntop(netmask)
		self.mac_addr = mac_addr
		self.mac_name = mac_name
	end

	#
	# Returns a pretty string representation of the interface's properties.
	#
	def pretty
		return sprintf(
				"#{mac_name}\n" +
				"Hardware MAC: %02x:%02x:%02x:%02x:%02x:%02x\n" +
				"IP Address  : %s\n" +
				"Netmask     : %s\n" +
				"\n", 
				mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], 
				mac_addr[4], mac_addr[5], ip, netmask)
	end

	#
	# The IP address bound to the interface.
	#
	attr_accessor :ip
	#
	# The subnet mask associated with the interface.
	#
	attr_accessor :netmask
	#
	# The physical (MAC) address of the NIC.
	#
	attr_accessor :mac_addr
	#
	# The name of the interface.
	#
	attr_accessor :mac_name

end

end; end; end; end; end; end