##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Smtp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'SMTP Banner Grabber',
			'Version'     => '',
			'Description' => 'SMTP Banner Grabber',
			'References'  =>
				[
					['URL', 'http://www.ietf.org/rfc/rfc2821.txt'],
				],
			'Author'      => 'CG',
			'License'     => MSF_LICENSE
		)
		deregister_options('MAILFROM', 'MAILTO')

	end

	def run_host(target_host)

		begin
		
			res = connect(true)

		if res 
			report_note(
				:host	=> target_host,
				:proto	=> 'SMTP',
				:port	=> rport,
				:type	=> 'BANNER',
				:data	=> banner.strip!
			)

			print_status("#{target_host}:#{rport} is running (#{banner})")

		end

		disconnect
		
		rescue ::Interrupt
			raise $!
		rescue ::Rex::ConnectionError, ::IOError
		end	
	end
end
