##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'
require 'scruby'
require 'packetfu'
require 'timeout'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Ip
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'IPID Sequence Scanner',
			'Description' => %q{
				This module will probe hosts' IPID sequences and classify
				them using the same method Nmap uses when it's performing
				its IPID Idle Scan (-sI) and OS Detection (-O).

				Nmap's probes are SYN/ACKs while this module's are SYNs.
				While this does not change the underlying functionality,
				it does change the chance of whether or not the probe
				will be stopped by a firewall.

				Nmap's Idle Scan can use hosts whose IPID sequences are
				classified as "Incremental" or "Broken little-endian incremental".
			},
			'Author'      => 'kris katterjohn',
			'License'     => MSF_LICENSE,
			'Version'     => '$Revision$' # 03/28/2009
		)

		begin
			require 'pcaprub'
			@@havepcap = true
		rescue ::LoadError
			@@havepcap = false
		end

		register_options([
			Opt::RPORT(80),
			OptInt.new('TIMEOUT', [true, "The reply read timeout in milliseconds", 500])
		])
	end

	def rport
		datastore['RPORT'].to_i
	end

	def run_host(ip)
		socket = connect_ip(false)
		return if not socket

		raise "Pcaprub is not available" if not @@havepcap

		pcap = ::Pcap.open_live(::Pcap.lookupdev, 68, false, 1)

		shost = Rex::Socket.source_address(ip)

		to = (datastore['TIMEOUT'] || 500).to_f / 1000.0

		ipids = []

		6.times do
			sport = rand(0xffff - 1025) + 1025

			probe = buildprobe(shost, sport, ip, rport)

			socket.sendto(probe, ip)

			pcap.setfilter(getfilter(shost, sport, ip, rport))

			reply = readreply(pcap, to)

			next if not reply

			ipids << reply.ip_id
		end

		disconnect_ip(socket)

		return if ipids.empty?

		print_status("#{ip}'s IPID sequence class: #{analyze(ipids)}")
	end

	# Based on Nmap's get_ipid_sequence() in osscan2.cc
	def analyze(ipids)
		allzeros = true
		allsame = true
		mul256 = true
		inc = true

		#ipids.each do |ipid|
		#	print_status("Got IPID ##{ipid}")
		#end

		return "Unknown" if ipids.size < 2

		diffs = []
		i = 1

		while i < ipids.size
			p = ipids[i - 1]
			c = ipids[i]

			if p != 0 or c != 0
				allzeros = false
			end

			if p <= c
				diffs[i - 1] = c - p
			else
				diffs[i - 1] = c - p + 65536
			end

			if ipids.size > 2 and diffs[i - 1] > 20000
				return "Randomized"
			end

			i += 1
		end

		return "All zeros" if allzeros

		diffs.each do |diff|
			if diff > 1000 and ((diff % 256) != 0 or ((diff % 256) == 0 and diff >= 25600))
				return "Random positive increments"
			end

			allsame = false if diff != 0

			mul256 = false if diff > 5120 or (diff % 256) != 0

			inc = false if diff >= 10
		end

		return "Constant" if allsame

		return "Broken little-endian incremental!" if mul256

		return "Incremental!" if inc

		"Unknown"
	end

	def getfilter(shost, sport, dhost, dport)
		"tcp and src host #{dhost} and src port #{dport} and " +
		"dst host #{shost} and dst port #{sport}"
	end

	def buildprobe(shost, sport, dhost, dport)
		(
			Scruby::IP.new(
				:src   => shost,
				:dst   => dhost,
				:proto => 6,
				:len   => 40,
				:id    => rand(0xffff)
			) / Scruby::TCP.new(
				:sport => sport,
				:dport => dport,
				:seq   => rand(0xffffffff)
			)
		).to_net
	end

	def readreply(pcap, to)
		reply = nil

		begin
			timeout(to) do
				pcap.each do |r|
					reply = PacketFu::Packet.parse(r)
					break
				end
			end
		rescue TimeoutError
		end

		return reply
	end
end

