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

	include Msf::Exploit::Remote::Ip
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
			'Version'     => '$Revision: 7197',
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
	end

	def run_host(ip)
		socket = connect_ip(false)
		return if not socket
		socket.sendto( build_tcp_syn(ip), ip)
		socket.sendto( build_icmp(ip),    ip)
		disconnect_ip(socket)
	end

	def build_tcp_syn(dst)
		n = Racket::Racket.new

		n.l3 = Racket::IPv4.new
		n.l3.src_ip = datastore['EHOST']
		n.l3.dst_ip = dst
		n.l3.protocol = 0x6
		n.l3.id = rand(0x10000)

		n.l4 = Racket::TCP.new
		n.l4.src_port = datastore['CPORT'].to_i
		n.l4.seq = Rex::Socket.addr_atoi(dst)
		n.l4.dst_port = datastore['RPORT'].to_i
		n.l4.flag_syn = 1

		n.l4.fix!(n.l3.src_ip, n.l3.dst_ip, "")

		n.pack
	end

	def build_icmp(dst)
		n = Racket::Racket.new

		n.l3 = Racket::IPv4.new
		n.l3.src_ip = datastore['EHOST']
		n.l3.dst_ip = dst
		n.l3.protocol = 0x1
		n.l3.id = rand(0x10000)

		n.l4 = Racket::ICMP.new
		n.l4.type = 8
		n.l4.id   = datastore['ECHOID'].to_i
		n.l4.seq  = 1
		n.l4.payload = Rex::Socket.addr_aton(dst) + Rex::Text.rand_text(28)

		n.l4.fix!

		n.pack
	end
end

