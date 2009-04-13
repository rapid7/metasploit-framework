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
require 'scruby'
require 'packetfu'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Ip
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'TCP SYN Port Scanner',
			'Description' => %q{
				Enumerate open TCP services using a raw SYN scan.
			},
			'Author'      => 'kris katterjohn',
			'Version'     => '$Revision$', # 03/26/2009
			'License'     => MSF_LICENSE
		)

		begin
			require 'pcaprub'
			@@havepcap = true
		rescue ::LoadError
			@@havepcap = false
		end

		register_options([
			OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "1-10000"]),
			OptInt.new('TIMEOUT', [true, "The reply read timeout in milliseconds", 500]),
			OptInt.new('BATCHSIZE', [true, "The number of hosts to scan per set", 256])
		], self.class)
	end

	def run_batch_size
		datastore['BATCHSIZE'] || 256
	end

	def run_batch(hosts)
		socket = connect_ip(false)
		return if not socket

		raise "Pcaprub is not available" if not @@havepcap

		pcap = ::Pcap.open_live(::Pcap.lookupdev, 68, false, 1)

		ports = Rex::Socket.portspec_crack(datastore['PORTS'])

		if ports.empty?
			print_error("Error: No valid ports specified")
			return
		end

		to = (datastore['TIMEOUT'] || 500).to_f / 1000.0

		# Spread the load across the hosts
		ports.each do |dport|
			hosts.each do |dhost|
				shost, sport = getsource(dhost)

				pcap.setfilter(getfilter(shost, sport, dhost, dport))

				begin
					probe = buildprobe(shost, sport, dhost, dport)

					socket.sendto(probe, dhost)

					reply = readreply(pcap, to)

					next if not reply

					if not reply.tcp_flags.syn.zero? and not reply.tcp_flags.ack.zero?
						# w00t!
						print_status(" TCP OPEN #{dhost}:#{dport}")
						report_service(:host => dhost, :port => dport)
					end
				rescue ::Exception
					print_error("Error: #{$!.class} #{$!}")
				end
			end
		end

		disconnect_ip(socket)
	end

	def getfilter(shost, sport, dhost, dport)
		# Look for associated SYN/ACKs and RSTs
		"tcp and (tcp[13] == 0x12 or (tcp[13] & 0x04) != 0) and " +
		"src host #{dhost} and src port #{dport} and " +
		"dst host #{shost} and dst port #{sport}"
	end

	def getsource(dhost)
		# srcip, srcport
		[ Rex::Socket.source_address(dhost), rand(0xffff - 1025) + 1025 ]
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

