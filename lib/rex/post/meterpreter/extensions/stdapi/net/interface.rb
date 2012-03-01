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
	def initialize(index, ip, netmask, mac_addr, mac_name, ip6=nil, netmask6=nil, mtu=nil, flags=nil)
		self.index    = index || -1
		self.ip       = (ip ? IPAddr.ntop(ip) : nil)
		self.netmask  = (netmask ? IPAddr.ntop(netmask) : nil)
		self.mac_addr = mac_addr
		self.mac_name = mac_name
		self.ip6      = (ip6 ? IPAddr.new_ntoh(ip6).to_s : nil)
		self.netmask6 = (netmask6 ? IPAddr.new_ntoh(netmask6).to_s : nil)
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

		info = [
			["Name"         , mac_name  ],
			["Hardware MAC" , sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				macocts[0], macocts[1], macocts[2],
				macocts[3], macocts[4], macocts[5])],
			["MTU"          , mtu       ],
			["Flags"        , flags     ],
			["IPv4 Address" , ((ip and ip != "0.0.0.0") ? ip : nil) ],
			["IPv4 Netmask" , netmask   ],
			["IPv6 Address" , ((ip6 and ip6 != "::") ? ip6 : nil) ],
			["IPv6 Netmask" , ((netmask6 and netmask6 != "::") ? netmask6 : nil) ],
		]
		pad = info.map{|i| i[0] }.max_by{|k|k.length}.length

		ret = sprintf(
				"Interface %2d\n" +
				"============\n",
				index
			)

		info.map {|k,v|
			next if v.nil?
			ret << k.ljust(pad) + " : #{v}\n"
		}

		ret
	end

	#
	# The indedx of the interface.
	#
	attr_accessor :index
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
