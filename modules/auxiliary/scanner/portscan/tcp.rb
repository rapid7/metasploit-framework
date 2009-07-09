##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	
	def initialize
		super(
			'Name'        => 'TCP Port Scanner',
			'Version'     => '$Revision$',
			'Description' => 'Enumerate open TCP services',
			'Author'      => [ 'hdm', 'kris katterjohn' ],
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "1-10000"]),
			OptInt.new('TIMEOUT', [true, "The socket connect timeout in milliseconds", 1000])
		], self.class)
		
		deregister_options('RPORT')

	end

	
	def run_host(ip)
	
		timeout = datastore['TIMEOUT'].to_i

		ports = Rex::Socket.portspec_crack(datastore['PORTS'])

		if ports.empty?
			print_status("Error: No valid ports specified")
			return
		end

		ports.each do |port|

			begin
				s = connect(false,
					{
						'RPORT' => port,
						'RHOST' => ip,
						'ConnectTimeout' => (timeout / 1000.0)
					}
				)
				print_status(" TCP OPEN #{ip}:#{port}")
				report_service(:host => ip, :port => port)
				disconnect(s)
			rescue ::Interrupt
				raise $!
			rescue ::Rex::ConnectionError
			rescue ::Exception => e
				print_status("Unknown error: #{e.class} #{e}")
			end
		end
	end



end
