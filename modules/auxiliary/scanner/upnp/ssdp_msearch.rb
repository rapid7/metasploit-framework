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
			'Description' => 'Discover information from UPnP-enabled systems',
			'Author'      => [ 'todb', 'hdm'], # Original scanner module and vuln info reporter, respectively
			'License'     => MSF_LICENSE
		)

		register_options( [
			Opt::RPORT(1900),
			OptBool.new('REPORT_LOCATION', [true, 'This determines whether to report the UPnP endpoint service advertised by SSDP', false ])
		], self.class)
	end

	def rport
		datastore['RPORT']
	end

	def setup
		super
		@msearch_probe =
			"M-SEARCH * HTTP/1.1\r\n" +
			"Host:239.255.255.250:1900\r\n" +
			"ST:upnp:rootdevice\r\n" +
			"Man:\"ssdp:discover\"\r\n" +
			"MX:3\r\n" +
			"\r\n"
	end

	def scanner_prescan(batch)
		print_status("Sending UPnP SSDP probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
		@results = {}
	end

	def scan_host(ip)
		vprint_status "#{ip}:#{rport} - SSDP - sending M-SEARCH probe"
		scanner_send(@msearch_probe, ip, datastore['RPORT'])
	end

	def scanner_postscan(batch)
		print_status "No SSDP endpoints found." if @results.empty?

		@results.each_pair do |skey,res|
			sinfo = res[:service]
			next unless sinfo

			bits = []

			[ :server, :location, :usn ].each do |k|
				bits << res[:info][k] if res[:info][k]
			end

			desc = bits.join(" | ")
			sinfo[:info] = desc

			res[:vulns] = []

			if res[:info][:server].to_s =~ /MiniUPnPd\/1\.0([\.\,\-\~\s]|$)/mi
				res[:vulns] << {
					:name => "MiniUPnPd ProcessSSDPRequest() Out of Bounds Memory Access Denial of Service",
					:refs => [ 'CVE-2013-0229' ]
				}
			end

			if res[:info][:server].to_s =~ /MiniUPnPd\/1\.[0-3]([\.\,\-\~\s]|$)/mi
				res[:vulns] << {
					:name  => "MiniUPnPd ExecuteSoapAction memcpy() Remote Code Execution",
					:refs  => [ 'CVE-2013-0230' ],
					:port  => res[:info][:ssdp_port] || 80,
					:proto => 'tcp'
				}
			end

			if res[:info][:server].to_s =~ /Intel SDK for UPnP devices.*|Portable SDK for UPnP devices(\/?\s*$|\/1\.([0-5]\..*|8\.0.*|(6\.[0-9]|6\.1[0-7])([\.\,\-\~\s]|$)))/mi
				res[:vulns] << {
					:name => "Portable SDK for UPnP Devices unique_service_name() Remote Code Execution",
					:refs => [ 'CVE-2012-5958', 'CVE-2012-5959' ]
				}
			end

			if res[:vulns].length > 0
				vrefs = []
				res[:vulns].each do |v|
					v[:refs].each do |r|
						vrefs << r
					end
				end

				print_good("#{skey} SSDP #{desc} | vulns:#{res[:vulns].count} (#{vrefs.join(", ")})")
			else
				print_status("#{skey} SSDP #{desc}")
			end

			report_service( sinfo )

			res[:vulns].each do |v|
				report_vuln(
					:host  => sinfo[:host],
					:port  => v[:port]  || sinfo[:port],
					:proto => v[:proto] || 'udp',
					:name  => v[:name],
					:info  => res[:info][:server],
					:refs  => v[:refs]
				)
			end

			if res[:info][:ssdp_host]
				report_service(
					:host  => res[:info][:ssdp_host],
					:port  => res[:info][:ssdp_port],
					:proto => 'tcp',
					:name  => 'upnp',
					:info  => res[:info][:location].to_s
				) if datastore['REPORT_LOCATION']
			end
		end
	end

	def scanner_process(data, shost, sport)

		skey = "#{shost}:#{datastore['RPORT']}"

		@results[skey] ||= {
			:info    => { },
			:service => {
				:host  => shost,
				:port  => datastore['RPORT'],
				:proto => 'udp',
				:name  => 'ssdp'
			}
		}

		if data =~ /^Server:[\s]*(.*)/i
			@results[skey][:info][:server] = $1.strip
		end

		ssdp_host = nil
		ssdp_port = 80
		location_string = ''
		if data =~ /^Location:[\s]*(.*)/i
			location_string = $1
			@results[skey][:info][:location] = $1.strip
			if location_string[/(https?):\x2f\x2f([^\x5c\x2f]+)/]
				ssdp_host,ssdp_port = $2.split(":") if $2.respond_to?(:split)
				if ssdp_port.nil?
					ssdp_port = ($1 == "http" ? 80 : 443)
				end

				if ssdp_host and ssdp_port
					@results[skey][:info][:ssdp_host] = ssdp_host
					@results[skey][:info][:ssdp_port] = ssdp_port.to_i
				end

			end
		end

		if data =~ /^USN:[\s]*(.*)/i
			@results[skey][:info][:usn] = $1.strip
		end

	end


end
