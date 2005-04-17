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
# Interface
# ---------
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
	
	def initialize(ip, netmask, mac_addr, mac_name)
		self.ip       = IPAddr.ntop(ip)
		self.netmask  = IPAddr.ntop(netmask)
		self.mac_addr = mac_addr
		self.mac_name = mac_name
	end

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

	attr_accessor :ip, :netmask, :mac_addr, :mac_name

end

end; end; end; end; end; end
