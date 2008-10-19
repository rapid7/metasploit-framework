#!/usr/bin/env ruby
# Copyright (C) 2007 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 

module Scruby
class Conf

	attr_accessor :iface
	attr_accessor :gateway_hwaddr
	attr_accessor :promisc

	def initialize
		# Default input/output interface
		@iface = 'eth0'

		# MAC address of the gateway
		@gateway_hwaddr = '00:00:00:00:00:00'

		# Sniff in promiscous mode or not
		@promisc = true

		# The default interface will be the first interface found with 
		# Pcap.pcap_lookupdev(), except on Windows where it will be the
		# second one.
		# NB: this doesn't work yet
		#
		#if $IS_WINDOWS
		#  alldevs = Pcap.findalldevs(devs, err)
		#  @iface = alldevs[1]
		#else
		#  @iface = Pcap.pcap_lookupdev
		#end

		# If any error occurred
		#if not err.nil?
		#  puts "Pcap: can't lookup a network device: #{err} (are you root/Administrator?)"
		#end
	end

	# Displays the configuration parameters
	def to_s
		out = ''

		# @iface may still be nil (e.g. if running with non-root/Adminitrator rights)
		iface = @iface.nil? ? '<none>' : @iface

		out += "iface (default interface): #{iface.to_s}\n"
		out += "gateway_hwaddr (gateway Ethernet address): #{@gateway_hwaddr.to_s}\n"
		out += "promisc (promiscuous mode): #{@promisc.to_s}\n"

		return out
	end

end
end