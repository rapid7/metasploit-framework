##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        	=> 'External IP',
			'Version'     	=> '$Revision: $',
			'Description'	=> 'This module checks for the public source IP address of the current route to the RHOST',
			'Author'        => ['RageLtMan'],
			'License'	=> MSF_LICENSE,
			'References'	=>
				[
					[ 'URL', 'http://ifconfig.me/ip' ],
				]
		)

		register_options(
			[
				OptEnum.new('RHOSTS', [true, 'The ifconfig.me server to use','49.212.202.172',['49.212.202.172','133.242.129.236']]),
				OptString.new('VHOST', [true, "The VHOST to use", 'ifconfig.me' ]),
				OptBool.new('REPORT_HOST', [false, 'Add the found IP to the database', false])
			], self.class)
end

	def run_host(ip)


		begin
			agent = datastore['UserAgent']
			connect
			res = send_request_raw({'uri' => '/ip', 'method' => 'GET' })
			our_addr = res.body.strip
			if Rex::Socket.is_ipv4?(our_addr) or Rex::Socket.is_ipv6?(our_addr)
				print_good("Source ip to #{ip} is #{our_addr}")
				report_host(our_addr) if datastore['REPORT_HOST']
			end

		end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::EHOSTUNREACH =>e
			puts e.message
		end
	end

