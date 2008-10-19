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
	SCRUBY_VERSION = '0.3-hdm'

	# Completion for functions
	FUNCTIONS_LIST = %w[sendp sniff ls lsc]

	# Link types that are not implented in Pcap
	DLT_OPENBSD = 12

	# Pcap::DLT_IEEE802 is 6 but on my system, sniffing on ath0 return 105 as link type
	DLT_IEEE80211 = 105

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

	# If two layers are to be bound every time
	BIND_ALWAYS = ''

	# Constants for Ethernet
	ETHERTYPE_IPv4 = 0x800
	ETHERTYPE_ARP = 0x806
	ETHERTYPE_ALL = { ETHERTYPE_IPv4 => 'IPv4',
			  ETHERTYPE_ARP => 'ARP' }
	ETHERADDR_ANY = '00:00:00:00:00:00'

	# Constants for ARP
	ARPTYPE_WHOAS = 1
	ARPTYPE_ISAT = 2
	ARPTYPE_RARP_REQ = 3
	ARPTYPE_RARP_RES = 4
	ARPTYPE_DYN_RARP_REQ = 5
	ARPTYPE_DYN_RARP_REP = 6
	ARPTYPE_DYN_RARP_ERR = 7
	ARPTYPE_IN_ARP_REQ = 8
	ARPTYPE_IN_ARP_REP = 9

	ARPTYPE_ALL = { ARPTYPE_WHOAS => 'who-as',
        	        ARPTYPE_ISAT => 'is-at',
	                ARPTYPE_RARP_REQ => 'RARP-req',
	                ARPTYPE_RARP_RES => 'RARP-rep',
	                ARPTYPE_DYN_RARP_REQ => 'DynRARP-req',
	                ARPTYPE_DYN_RARP_REP => 'DynRARP-rep',
	                ARPTYPE_DYN_RARP_ERR => 'DynRARP-err',
	                ARPTYPE_IN_ARP_REQ => 'InARP-req',
        	        ARPTYPE_IN_ARP_REP => 'InARP-rep' }

	ARPHWTYPE_ETHER = 1
	ARPHWTYPE_FRAME_RELAY = 15
	ARPHWTYPE_ALL = { ARPHWTYPE_ETHER => 'Ethernet',
        	          ARPHWTYPE_FRAME_RELAY => 'FrameRelay' }

	ARPHWLEN_TOKEN_RING = 1
	ARPHWLEN_ETHER = 6
	ARPHWLEN_ALL = { ARPHWLEN_TOKEN_RING => 'TokenRing',
	                 ARPHWLEN_ETHER => 'Ethernet' }

	ARPPROTOLEN_IPv4 = 4
	ARPPROTOLEN_IPv6 = 16
	ARPPROTOLEN_ALL = { ARPPROTOLEN_IPv4 => 'IPv4',
	                    ARPPROTOLEN_IPv6 => 'IPv6' }

	# Constants for BSD loopback interfaces
	BSDLOOPBACKTYPE_IPv4 = 2

	# Constants for IP
	IPFLAGS = %w[MF DF evil]

	IPPROTO_ICMP = 1
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
	IPPROTO_ALL = { IPPROTO_ICMP => 'ICMP',
                	IPPROTO_TCP => 'TCP',
                	IPPROTO_UDP => 'UDP' }

	# Constants for TCP
	TCPFLAGS = %w[FIN SYN RST PSH ACK URG ECN RES]

	# Constants for ICMP
	ICMPTYPE_ECHO_REQ = 8
	ICMPTYPE_ALL = { ICMPTYPE_ECHO_REQ => 'echo request' }

	# Constants for 802.11
	DOT11TYPE_MANAGEMENT = 0
	DOT11TYPE_CONTROL = 1
	DOT11TYPE_DATA = 2
	DOT11TYPE_RESERVED = 3

	DOT11TYPE_ALL = { DOT11TYPE_MANAGEMENT => 'Management',
	                  DOT11TYPE_CONTROL => 'Control',
	                  DOT11TYPE_DATA => 'Data',
	                  DOT11TYPE_RESERVED => 'Reserved' }

	DOT11SUBTYPE_PS_POLL = 0b1010
	DOT11SUBTYPE_RTS = 0b1011
	DOT11SUBTYPE_CF_END = 0b1110
	DOT11SUBTYPE_CF_END_CF_ACK = 0b1111

	DOT11_FC_FLAGS = %w[to-DS from-DS MF retry pw-mgt MD wep order]

	DOT11_CAPABILITIES = %w[res8 res9 short-slot res11 res12 DSSS-OFDM res14 res15 ESS IBSS CFP CFP-req privacy short-preamble PBCC agility]

	DOT11_ID = {0 => 'SSID', 1 => 'Rates', 2 =>  'FHset', 3 => 'DSset', 4 => 'CFset', 5 => 'TIM', 6 => 'IBSSset', 16 => 'challenge', 42 => 'ERPinfo', 46 => 'QoS Capability', 47 => 'ERPinfo', 48 => 'RSNinfo', 50 => 'ESRates',221 => 'vendor',68 => 'reserved'}

	DOT11_REASON = {0 => 'reserved',1 => 'unspec', 2 => 'auth-expired',
	               3 => 'deauth-ST-leaving',
	               4 => 'inactivity', 5 => 'AP-full', 6 => 'class2-from-nonauth',
	               7 => 'class3-from-nonass', 8 => 'disas-ST-leaving',
	               9 => 'ST-not-auth'}

	DOT11_AUTH_ALGO = {0 => 'open', 1 => 'sharedkey'}

	DOT11_STATUS = {0 => 'success', 1 => 'failure', 10 => 'cannot-support-all-cap',
	               11 => 'inexist-asso', 12 => 'asso-denied', 13 => 'algo-unsupported',
	               14 => 'bad-seq-num', 15 => 'challenge-failure',
	               16 => 'timeout', 17 => 'AP-full', 18 => 'rate-unsupported'}

	RADIOTAP_PRESENT = %w[TSFT Flags Rate Channel FHSS dBm_AntSignal dBm_AntNoise Lock_Quality TX_Attenuation dB_TX_Attenuation
                      dBm_TX_Power Antenna dB_AntSignal dB_AntNoise
                      b14 b15 b16 b17 b18 b19 b20 b21 b22 b23
                      b24 b25 b26 b27 b28 b29 b30 Ext]

	def self.aware_proto
		@@aware_proto
	end
end