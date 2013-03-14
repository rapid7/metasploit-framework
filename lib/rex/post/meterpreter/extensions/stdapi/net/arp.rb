#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'ipaddr'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net

###
#
# This class represents an arp entry
# on the remote machine.
#
###
class Arp

	##
	#
	# Constructor
	#
	##

	#
	# Returns an arp entry and initializes it to the supplied
	# parameters.
	#
	def initialize(opts={})
		self.ip_addr   = IPAddr.new_ntoh(opts[:ip_addr]).to_s
		self.mac_addr  = mac_to_string(opts[:mac_addr])
		self.interface = opts[:interface]
	end

	def mac_to_string(mac_addr)
		macocts = []
		mac_addr.each_byte { |o| macocts << o }
		macocts += [0] * (6 - macocts.size) if macocts.size < 6
		return sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			macocts[0], macocts[1], macocts[2],
			macocts[3], macocts[4], macocts[5])
	end

	#
	# The ip address corresponding to the arp address.
	#
	attr_accessor :ip_addr
	#
	# The physical (MAC) address of the ARP entry
	#
	attr_accessor :mac_addr
	#
	# The name of the interface.
	#
	attr_accessor :interface
end

end; end; end; end; end; end
