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
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Rogue Gateway Detection: Sender',
			'Description' => %q{
				This module send a series of TCP SYN and ICMP ECHO requests
			to each internal target host, spoofing the source address of an external
			system running the rogue_recv module. This allows the system running
			the rogue_recv module to determine what external IP a given internal
			system is using as its default route.
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
			OptAddress.new("EHOST", [true, "The IP address of the machine running rogue_recv"]),
			OptPort.new("RPORT", [true, "The destination port for the TCP SYN packet", 80]),
			OptPort.new("CPORT", [true, "The source port for the TCP SYN packet", 13832]),
			OptInt.new("ECHOID", [true, "The unique ICMP ECHO ID to embed into the packet", 7893]),
		])
		
		deregister_options('FILTER','PCAPFILE')
	end

	def run_host(ip)
		pcap = open_pcap

		dst_mac,src_mac = lookup_eth(ip)
		if dst_mac == "ff:ff:ff:ff:ff:ff"
			print_error("#{ip}: Not reponding to ARP.")
			return
		end

		inject_eth(:payload => build_tcp_syn(ip),
							 :eth_daddr => dst_mac,
							 :eth_saddr => src_mac
							)

		inject_eth(:payload => build_icmp(ip),
							 :eth_daddr => dst_mac,
							 :eth_saddr => src_mac
							)

		close_pcap
	end

	def build_tcp_syn(dst)
		n = Racket::Racket.new

		n.l3 = Racket::L3::IPv4.new
		n.l3.src_ip = datastore['EHOST']
		n.l3.dst_ip = dst
		n.l3.protocol = 0x6
		n.l3.id = rand(0x10000)
		n.l3.ttl = 255

		n.l4 = Racket::L4::TCP.new
		n.l4.src_port = datastore['CPORT'].to_i
		n.l4.seq = Rex::Socket.addr_atoi(dst)
		n.l4.dst_port = datastore['RPORT'].to_i
		n.l4.flag_syn = 1

		n.l4.fix!(n.l3.src_ip, n.l3.dst_ip, "")

		n.pack
	end

	def build_icmp(dst)
		n = Racket::Racket.new

		n.l3 = Racket::L3::IPv4.new
		n.l3.src_ip = datastore['EHOST']
		n.l3.dst_ip = dst
		n.l3.protocol = 0x1
		n.l3.id = rand(0x10000)
		n.l3.ttl = 255

		n.l4 = Racket::L4::ICMP.new
		n.l4.type = 8
		n.l4.id   = rand(0x10000)
		n.l4.seq  = 1
		n.l4.payload = Rex::Socket.addr_aton(dst) + [datastore['ECHOID']].pack('n') + Rex::Text.rand_text(26)

		n.l4.fix!

		n.pack
	end
end

