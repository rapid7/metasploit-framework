#!/usr/bin/env ruby
# Copyright (C) 2007 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 

module Scruby

	# Sniff packets on an interface
	def sniff(args = Hash.new())

		# Default parameter values
		params = {
			:iface => @conf.iface,
			:prn => :sniff_simple,
			:filter => nil,
			:count => -1,
			:promisc => @conf.promisc,
			:timeout => TIMEOUT,
			:offline => nil
		}

		# Overwriting default values with user-supplied ones
		params.merge!(args)

		# Sniffing the network...
		if params[:offline].nil?

			# Can't sniff without a valid interface
			if params[:iface].nil?
				puts "Pcap: can't find a valid interface. Remember this function must be run as root/Administrator."
				return
			end

			# Opening the network interface with PCAP 
			begin
				pcap = Pcap::open_live(params[:iface], MTU, params[:promisc], params[:timeout])
				puts "listening on #{params[:iface]}"

			rescue Exception => e
				puts "Pcap: can't open device '#{params[:iface]}' (#{e})"
				return
			end

		# ... or reading the provided PCAP file
		else
			begin
				pcap = Pcap::open_offline(params[:offline])
				puts "reading from #{params[:offline]}"

			rescue Exception => e
				puts "Pcap: can't read file (#{e})"
				return
			end
		end

		# PCAP filtering
		if not params[:filter].nil?
			begin
				pcap.setfilter(params[:filter])
			rescue Exception => e
				puts "Pcap: can't set filter '#{params[:filter]}' (#{e})"
				return
			end
		end

		# Sniffing/reading in progress
		begin
			pcap.each do |packet|

				# Calling the method defined in "prn"
				self.__send__(params[:prn], pcap, packet)

				# Handling the number of packets to process
				params[:count] -= 1
				if params[:count] == 0
					break
				end

			end

		# ^C to stop sniffing
		rescue Interrupt
			puts "\nStopped by user."

		rescue Exception => e
			puts "\nERROR: #{e} #{e.backtrace}"
			retry
		end
	end

	# Default callback function for the sniff method (simple packet display)
	def sniff_simple(pcap, packet)

		# Getting the link type
		linktype = pcap.datalink

		# Getting current date and time (epoch)
		# NB: this should be retrieved from the PCAP structure...
		date_time = Time.new.to_f.to_s + ' '

		dec = Scruby.linklayer_dissector(pcap.datalink, packet)
	
		if(dec)
			puts date_time + dec.to_s
		else
			puts "Unknown link type: #{linktype}"
			puts "raw packet=|#{packet.inspect}| "
			puts
		end
	end

	# Sends a packet at layer 3 (will not work yet)
	def send_xxx(packet)

		iface = @conf.iface

		# Can't do anything without a valid interface
		if iface.nil?
			puts "Pcap: can't find a valid interface. Remember this function must be run as root/Administrator."
			return
		end

		# Sending the packet with sendp
		# If we're sending on a loopback interface, we must be careful
		# because of the different fake headers.
		# The loopback device is "lo" on Linux and "lo0" on BSD; there is
		# no loopback device on Windows.
		# On BSD, a 4-byte header is used for loopback and there is a
		# special case for OpenBSD; on Linux, it is an Ethernet header.
		if @@IS_BSD and @conf.iface.include?(LOOPBACK_DEVICE_PREFIX)

			if @@IS_OPENBSD
				sendp(OpenBSDLoopback()/packet)
			else
				sendp(ClassicBSDLoopback()/packet)
			end

		else
			# Hum, this will create an incorrect packet if the upper layer is not IP...
			sendp(Ether()/packet)
		end
	end

	# Sends a packet at layer 2
	def sendp(packet)

		iface = @conf.iface
		promisc = @conf.promisc

		# Can't do anything without a valid interface
		if iface.nil?
			puts "Pcap: can't find a valid interface. Remember this function must be run as root/Administrator."
			return
		end

		# Default values
		ip_default_src = IP().src
		ether_default_src = Ether().src
		ether_default_dst = Ether().dst

		layer3_src = ip_default_src
		layer2_src = ether_default_src
		layer2_dst = @conf.gateway_hwaddr

		# Getting source information with Libdnet if available
		#if $HAVE_LIBDNET
			#iface_info = Net::Libdnet::intf_get(@conf.iface)

			#if iface_info.addr.nil?
			#  puts "Libdnet: interface '#{@conf.iface}' is not valid."
			#end

			# addr field is "a.b.c.d/mask", splitting at '/'
			#layer3_src = iface_info.addr.split(/\//)
			#layer2_src = iface_info.link_addr
		#end

		# Destination MAC is taken from the configuration. On Linux, if the
		# packet is to be sent on the loopback device, this must be null.
		if @@IS_LINUX and @conf.iface.include?(LOOPBACK_DEVICE_PREFIX)
			layer2_dst = ether_default_src
		end

		# Modifying the Ethernet layer (only if the values are the default ones)
		# If the first layer is Ethernet and src/dst are the default values
		if packet.is_a?(Ether) and packet.dst == ether_default_dst
			packet.dst = layer2_dst

		# If packet is a Packet with Ethernet as a first layer
		elsif packet.is_a?(Packet) and packet.layers_list[0].is_a?(Ether) and packet.layers_list[0].dst == ether_default_dst
			packet.layers_list[0].dst = layer2_dst
		end

		# Opening the interface
		begin
			pcap = Pcap::open_live(iface, MTU, @conf.promisc, TIMEOUT)

		rescue Exception => e
			puts "Pcap: can't open device '#{iface}' (#{e})"
			return
		end

		# Packing the packet
		packet_string = packet.to_net

		# Sending the packet with PCAP
		begin
			pcap.inject(packet_string)
			puts "Sent on #{iface}."

		rescue Exception => e
			puts "Pcap: error while sending packet on '#{iface}' (#{e})"
		end

	end

	# Lists all available dissectors. If one of them is passed as an
	# argument, it is described.
	def ls(arg = nil)

		if arg.nil?
			puts "Available dissectors:"
			Scruby.dissectors.keys.sort.each do |dissector|
				puts "\t"+dissector
			end

			puts "\nType \"ls 'MyDissector'\" to have detailed information on one of them."

		else
			arg = (arg.class == Class) ? arg.new : arg
			dis = arg.class.to_s

			if(not Scruby.get_dissector(dis))
				raise ArgumentError, "could not obtain the field list for #{dis}'"
			end

			instance = arg
			puts "Field name\tField type\tDefault value"

			instance.fields_desc.each do |field|
				puts field.name + "\t\t" + field.class.to_s.split('::')[1] + "\t" + field.to_human(field.default_value) + "\n"
			end

			puts
		end
	end

	# Lists all available functions. If one of them is passed as an
	# argument, the help function is run.
	def lsc(arg = nil)

		if arg.nil?
			puts "Available commands:"
			Scruby.function_list.each do |function|
				puts function
			end

			puts "\nType \"lsc 'mycommand'\" to have detailed information."

		else
			eval(arg.to_s + '_help')
		end
	end

	# Converts a packet to a string
	def str(packet)
		puts "In Scruby, type 'mypacket.to_net' instead"
	end

end