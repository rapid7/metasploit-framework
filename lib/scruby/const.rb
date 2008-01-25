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

	# Scruby version
	SCRUBY_VERSION = '0.2.1-hdm-2'

	# Completion for functions
	FUNCTIONS_LIST = %w[sendp sniff ls lsc]

	# History
	RECORD_HISTORY = true

	# Only some protocols need to be aware of upper layers
	@@aware_proto = %w[IPv4 TCP ICMP UDP]

	# Default options for packet capture
	MTU = 1500
	FOREVER = -1
	# TIMEOUT = 0 seems to be a problem on some platforms
	TIMEOUT = 1
	LOOPBACK_DEVICE_PREFIX = 'lo'

	# Constants for Ethernet
	ETHERTYPE_IPv4 = 0x800
	ETHERTYPE_ALL = { ETHERTYPE_IPv4 => "IPv4"}

	# Constants for BSD loopback interfaces
	BSDLOOPBACKTYPE_IPv4 = 2

	# Constants for IP
	IPPROTO_ICMP = 1
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
	IPPROTO_ALL = { IPPROTO_ICMP => "ICMP",
                	IPPROTO_TCP => "TCP",
                	IPPROTO_UDP => "UDP" }

	# Constants for ICMP
	ICMPTYPE_ECHO = 8

	def self.aware_proto
		@@aware_proto
	end
end
