##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'racket'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Capture

	def initialize
		super(
			'Name'        => 'Rogue Gateway Detection: Receiver',
			'Description' => %q{
				This module listens for replies to the requests sent by
			the rogue_send module. The RPORT, CPORT, and ECHOID values
			must match the rogue_send parameters used exactly.
			},
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE,
			'Version'     => '$Revision$',
			'References'  =>
				[
					['URL', 'http://www.metasploit.com/research/projects/rogue_network/'],
				]
		)

		register_options([
			OptPort.new("RPORT", [true, "The destination port for the TCP SYN packet", 80]),
			OptPort.new("CPORT", [true, "The source port for the TCP SYN packet", 13832]),
			OptInt.new("ECHOID", [true, "The unique ICMP ECHO ID to embed into the packet", 7893]),
		])
	end

	def build_filter
		"icmp or (" +
			"tcp and (tcp[13] == 0x12 or (tcp[13] & 0x04) != 0) and " +
			"src port #{datastore['RPORT']} and dst port #{datastore['CPORT']} " +
		")"
	end

	def run
		print_status("Opening the capture interface...")
		open_pcap('SNAPLEN' => 128, 'FILTER' => build_filter)

		print_status("Waiting for responses to rogue_send...")
		begin
		each_packet do |pkt|
			r = parse_reply(pkt)
			next if not r
			print_status("Reply from #{r[:internal]} using gateway #{r[:external]} (#{r[:type].to_s.upcase})")
		end
		rescue ::Interrupt
			raise $!
		ensure
			close_pcap
		end
	end

	def parse_reply(r)
		eth = Racket::L2::Ethernet.new(r)
		return if not eth.ethertype == 0x0800

		ip = Racket::L3::IPv4.new(eth.payload)
		case ip.protocol
		when 1
			icmp = Racket::L4::ICMP.new(ip.payload)
			reply = {:raw => r, :eth => eth, :ip => ip, :icmp => icmp}
			reply[:type]     = :icmp
			return if(icmp.payload[4,2] != [datastore['ECHOID']].pack('n'))
			reply[:internal] = Rex::Socket.addr_ntoa(icmp.payload[0,4])
			reply[:external] = ip.src_ip
			return reply
		when 6
			tcp = Racket::L4::TCP.new(ip.payload)
			reply = {:raw => r, :eth => eth, :ip => ip, :tcp => tcp}
			reply[:type]     = :tcp
			reply[:internal] = Rex::Socket.addr_itoa(tcp.ack - 1)
			reply[:external] = ip.src_ip
			return reply
		end
		return
	end
end

