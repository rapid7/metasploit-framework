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

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::UDPScanner

	def initialize
		super(
			'Name'        => 'UPnP SSDP M-SEARCH Information Discovery',
			'Version'     => '$Revision$',
			'Description' => 'Discover information from UPnP-enabled systems',
			'Author'      => 'todb',
			'License'     => MSF_LICENSE
		)

		register_options( [
			Opt::RPORT(1900),
			OptBool.new('REPORT_LOCATION', [true, 'This determines whether to report the UPnP endpoint service advertised by SSDP', false ])
		], self.class)
	end

	def setup
		super
		@msearch_probe =
			"M-SEARCH * HTTP/1.1\r\n" +
			"Host:239.255.255.250:1900\r\n" +
			"ST:upnp:rootdevice\r\n" +
			"Man:\"ssdp:discover\"\r\n" +
			"MX:3\r\n" +
			"\r\n\r\n" # Non-standard, but helps
	end

	def scanner_prescan(batch)
		print_status("Sending UPnP SSDP probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
		@results = {}
	end

	def scan_host(ip)
		scanner_send(@msearch_probe, ip, datastore['RPORT'])
	end

	def scanner_process(data, shost, sport)

		skey = "#{shost}:#{datastore['RPORT']}"
		return if @results[skey]

		info = []
		if data =~ /^Server:[\s]*(.*)/
			info << $1.strip
		end

		ssdp_host = nil
		ssdp_port = 80
		location_string = ''
		if data =~ /^Location:[\s]*(.*)/
			location_string = $1
			info << location_string.to_s.strip
			if location_string[/(https?):\x2f\x2f([^\x5c\x2f]+)/]
				ssdp_host,ssdp_port = $2.split(":") if $2.respond_to?(:split)
				if ssdp_port.nil?
					ssdp_port = ($1 == "http" ? 80 : 443)
				end
			end
		end

		if data =~ /^USN:[\s]*(.*)/
			info << $1.strip
		end

		return unless info.length > 0

		desc = info.join(" | ")

		@results[skey] = {
			:host  => shost,
			:port  => datastore['RPORT'],
			:proto => 'udp',
			:name  => 'ssdp',
			:info  => desc
		}

		print_status("#{shost}:#{sport} SSDP #{desc}")
		report_service( @results[skey] )

		if ssdp_host
			report_service(
				:host  => ssdp_host,
				:port  => ssdp_port,
				:proto => 'tcp',
				:name  => 'upnp',
				:info  => location_string
			) if datastore['REPORT_LOCATION']
		end
	end


end
