###
# $Id$
###

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'         => 'BNAT Scanner',
			'Version'      => '$Revision$',
			'Description'  => %q{
					This module is a scanner which can detect Bad NAT (network address translation)
				implementations, which could result in a inability to reach ports on remote
				machines. Typically, these ports will appear in nmap scans as 'filtered'.
				},
			'Author'       =>
				[
					'bannedit',
					'Jonathan Claudius <jclaudius[at]trustwave.com>',
				],
			'License'      => MSF_LICENSE,
			'References'   =>
				[
					[ 'URL', 'https://github.com/claudijd/BNAT-Suite'],
					[ 'URL', 'http://www.slideshare.net/claudijd/dc-skytalk-bnat-hijacking-repairing-broken-communication-channels'],
				]
		)
		register_options(
				[
					OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "1-10000"]),
					OptString.new('INTERFACE', [true, 'The interface connected to the network', 'eth0']),
				],self.class)
	end

	def run_host(ip)
		synack_hash  = {}
		synack_array = []
		ftypes = %w{windows, linux, freebsd}
		@flavor = ftypes[rand(ftypes.length)] # we can randomize our flavor

		#Start Capture for !IP
		pcap = PacketFu::Capture.new(
		:iface => datastore['INTERFACE'],
		:start => true,
		:filter => "tcp and not host #{ip} and tcp[13] == 18")

		scan = Thread.new do
			iface = PacketFu::Utils.whoami?(:iface => datastore['INTERFACE'])
			ports = Rex::Socket.portspec_crack(datastore['PORTS'])

			tcp_pkt = PacketFu::TCPPacket.new(:config => iface, :timeout => 0.1, :flavor => @flavor)
			tcp_pkt.ip_daddr = ip
			tcp_pkt.tcp_flags.syn = 1

			#tcp_pkt.tcp_win = 14600
			# should be handled by the flavor config option
			#tcp_pkt.tcp_options = "MSS:1460,SACKOK,TS:3853;0,NOP,WS:5"

			ports.each do |port|
				tcp_pkt.tcp_src = rand(64511)+1024
				tcp_pkt.tcp_dst = port
				tcp_pkt.recalc
				tcp_pkt.to_w
				select(nil, nil, nil, 0.075)
				tcp_pkt.to_w
			end
		end

		analyze = Thread.new do
			loop do
				pcap.stream.each do |pkt|
					packet = PacketFu::Packet.parse(pkt)
					synack_hash = { :ip => packet.ip_saddr.to_s, :port => packet.tcp_sport.to_s}
					synack_array.push(synack_hash)
				end
			end
		end

		# Wait for the scan to complete
		scan.join
		select(nil, nil, nil, 0.05)
		analyze.terminate

		# Clean up any duplicate responses received
		synack_array = synack_array.uniq

		synack_array.each do |synack|
			print_status "[BNAT Response] Request: #{ip} Response: #{synack[:ip]} Port: #{synack[:port]}"
		end
	end
end

