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
			'Version'     => '$Revision$'
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

		register_advanced_options([
			OptInt.new('SAMPLES', [true, "The IPID sample size", 6])
		])
	end

	def rport
		datastore['RPORT'].to_i
	end

	def run_host(ip)
		raise "Pcaprub is not available" if not @@havepcap
		raise "SAMPLES option must be >= 2" if datastore['SAMPLES'] < 2

		socket = connect_ip(false)
		return if not socket

		pcap = ::Pcap.open_live(::Pcap.lookupdev, 68, false, 1)

		shost = Rex::Socket.source_address(ip)

		to = (datastore['TIMEOUT'] || 500).to_f / 1000.0

		ipids = []

		pcap.setfilter(getfilter(shost, ip, rport))

		datastore['SAMPLES'].times do
			sport = rand(0xffff - 1025) + 1025

			probe = buildprobe(shost, sport, ip, rport)

			socket.sendto(probe, ip)

			reply = readreply(pcap, to)

			next if not reply

			ipids << reply[:ip].id
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

		# ipids.each do |ipid|
		#	print_status("Got IPID ##{ipid}")
		# end

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

	def getfilter(shost, dhost, dport)
		"tcp and src host #{dhost} and src port #{dport} and " +
		"dst host #{shost}"
	end

	def buildprobe(shost, sport, dhost, dport)
		n = Racket::Racket.new

		n.l3 = Racket::IPv4.new
		n.l3.src_ip = shost
		n.l3.dst_ip = dhost
		n.l3.protocol = 0x6
		n.l3.id = rand(0x10000)

		n.l4 = Racket::TCP.new
		n.l4.src_port = sport
		n.l4.seq = rand(0x100000000)
		n.l4.dst_port = dport
		n.l4.flag_syn = 1

		n.l4.fix!(n.l3.src_ip, n.l3.dst_ip, "")

		n.pack
	end

	def readreply(pcap, to)
		reply = nil

		begin
			Timeout.timeout(to) do
				pcap.each do |r|
					eth = Racket::Ethernet.new(r)

					next if not eth.ethertype == 0x0800

					ip = Racket::IPv4.new(eth.payload)
					next if not ip.protocol == 6

					tcp = Racket::TCP.new(ip.payload)

					reply = {:raw => r, :eth => eth, :ip => ip, :tcp => tcp}

					break
				end
			end
		rescue Timeout::Error
		end

		return reply
	end

end

