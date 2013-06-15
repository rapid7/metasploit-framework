##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name' => 'SAPRouter Port Scanner',
			'Description' => %q{
					This module allows for mapping ACLs and identify open/closed ports accessible
				on hosts through a saprouter.
			},
			'Author' => [
				'Bruno Morisson <bm[at]integrity.pt>', # metasploit module
				'nmonkee' # saprouter packet building code from sapcat.rb
			],
			'References' =>
				[
					# General
					['URL', 'http://help.sap.com/saphelp_nw70/helpdata/EN/4f/992dfe446d11d189700000e8322d00/frameset.htm'],
					['URL', 'http://help.sap.com/saphelp_dimp50/helpdata/En/f8/bb960899d743378ccb8372215bb767/content.htm'],
					['URL', 'http://labs.mwrinfosecurity.com/blog/2012/09/13/sap-smashing-internet-windows/'],
					['URL', 'http://conference.hitb.org/hitbsecconf2010ams/materials/D2T2%20-%20Mariano%20Nunez%20Di%20Croce%20-%20SAProuter%20.pdf'],
					['URL', 'http://scn.sap.com/docs/DOC-17124'] # SAP default ports
				],
			'License' => MSF_LICENSE
		)

		register_options(
			[
				OptAddress.new('SAPROUTER_HOST', [true, 'SAPRouter address', '']),
				OptPort.new('SAPROUTER_PORT', [true, 'SAPRouter TCP port', '3299']),
				OptEnum.new('MODE', [true, 'Connection Mode: SAP_PROTO or TCP ', 'SAP_PROTO', ['SAP_PROTO', 'TCP']]),
				OptString.new('PORTS', [true, 'Ports to scan (e.g. 22-25,80,110-900)', '3200-3299']),
				OptInt.new('CONCURRENCY', [true, 'The number of concurrent ports to check per host', 10]),
			], self.class)

		deregister_options('RPORT')

	end

	def build_ni_packet(routes)

		mode = {'SAP_PROTO'=>0,'TCP'=>1}[datastore['MODE']]

		route_data=''
		ni_packet = [
			'NI_ROUTE',
			0,
			2,
			39,
			2,
			mode,
			0,
			0,
			1
		].pack("A8c8")

		first = false

		routes.each do |host, port| # create routes
			route_item = [host, 0, port.to_s, 0, 0].pack("A*CA*cc")
			if !first
				route_data = [route_data, route_item.length, route_item].pack("A*NA*")
				first = true
			else
				route_data = route_data << route_item
			end
		end

		ni_packet << [route_data.length - 4].pack('N') << route_data # add routes to packet
		ni_packet = [ni_packet.length].pack('N') << ni_packet # add size
	end

	def parse_response_packet(response, ip, port)

		#vprint_error("#{ip}:#{port} - response packet: #{response}")

		case response
		when /NI_RTERR/
			case response
			when /timed out/
				vprint_error ("#{ip}:#{port} - connection timed out")
			when /refused/
				vprint_error("#{ip}:#{port} - TCP closed")
				return [ip, port, "closed"]
			when /denied/
				vprint_error("#{ip}:#{port} - blocked by ACL")
			when /invalid/
				vprint_error("#{ip}:#{port} - invalid route")
			when /reacheable/
				vprint_error("#{ip}:#{port} - unreachable")
			else
				vprint_error("#{ip}:#{port} - unknown error message")
			end
		when /NI_PONG/
			print_good("#{ip}:#{port} - TCP OPEN")
			return [ip, port, "open"]
		else
			vprint_error("#{ip}:#{port} - unknown response")
		end

		return nil
	end

	def run_host(ip)

		ports = Rex::Socket.portspec_crack(datastore['PORTS'])

		sap_host = datastore['SAPROUTER_HOST']
		sap_port = datastore['SAPROUTER_PORT']

		if ports.empty?
			print_error('Error: No valid ports specified')
			return
		end

		print_status("Scanning #{ip}")
		thread = []
		r = []

		begin
		ports.each do |port|

			if thread.length >= datastore['CONCURRENCY']
				# Assume the first thread will be among the earliest to finish
				thread.first.join
			end
			thread << framework.threads.spawn("Module(#{self.refname})-#{ip}:#{port}", false) do

				begin
					# create ni_packet to send to saprouter
					routes = {sap_host => sap_port, ip => port}
					ni_packet = build_ni_packet(routes)

					s = connect(false,
						{
						'RPORT' => sap_port,
						'RHOST' => sap_host
						}
					)

					s.write(ni_packet, ni_packet.length)
					response = s.get()

					res = parse_response_packet(response, ip, port)
					if res
						r << res
					end

				rescue ::Rex::ConnectionRefused
					print_error("#{ip}:#{port} - Unable to connect to SAPRouter #{sap_host}:#{sap_port} - Connection Refused")

				rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error
				rescue ::Rex::Post::Meterpreter::RequestError
				rescue ::Interrupt
					raise $!
				ensure
					disconnect(s) rescue nil
				end
			end
		end
		thread.each { |x| x.join }

		rescue ::Timeout::Error
		ensure
			thread.each { |x| x.kill rescue nil }
		end

		r.each do |res|
			report_service(:host => res[0], :port => res[1], :state => res[2])
		end

	end

end
