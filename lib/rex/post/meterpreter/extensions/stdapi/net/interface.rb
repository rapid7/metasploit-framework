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
	def initialize(ip, netmask, mac_addr, mac_name,ip6=false,netmask6=false,mtu=0,flags = "")
		self.ip       = IPAddr.ntop(ip)
		self.netmask  = IPAddr.ntop(netmask)
		self.mac_addr = mac_addr
		self.mac_name = mac_name
		self.ip6      = ip6 ? IPAddr.new_ntoh(ip6).to_s : ""
		self.netmask6 = netmask6 ? IPAddr.new_ntoh(netmask6).to_s : ""
		self.mtu      = mtu
		self.flags    = flags
	end

	#
	# Returns a pretty string representation of the interface's properties.
	#
	def pretty
		macocts = []
		mac_addr.each_byte { |o| macocts << o }
		macocts += [0] * (6 - macocts.size) if macocts.size < 6
		if ip6 != ""
			ipv6_conf  = sprintf("IPv6 Address : %s\n" +
							 	 "Netmask      : %s\n", 
								  ip6, netmask6)
		else
			ipv6_conf = ""
		end
		if flags != ""
			flags_str =  sprintf("Flags        : %s\n", flags)
		else	
			flags_str = ""
		end
		return sprintf(
				"#{mac_name}\n" +
				"Hardware MAC : %02x:%02x:%02x:%02x:%02x:%02x\n" +
				"MTU          : %d\n" +
				"%s" +
				"IP Address   : %s\n" +
				"Netmask      : %s\n" +
				"%s" + 
				"\n",
				macocts[0], macocts[1], macocts[2], macocts[3],
				macocts[4], macocts[5], mtu, flags_str, ip, netmask, ipv6_conf)
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
	#
	# The IPv6 address bound to the interface.
	#
	attr_accessor :ip6
	#
	# The subnet mask associated with the IPv6 interface.
	#
	attr_accessor :netmask6
	#
	# The MTU associated with the interface.
	#
	attr_accessor :mtu
	#
	# The flags associated with the interface.
	#
	attr_accessor :flags
end

end; end; end; end; end; end
