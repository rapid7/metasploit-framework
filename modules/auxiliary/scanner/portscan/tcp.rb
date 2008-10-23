##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
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
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			OptPort.new('PORTSTART', [true, 'The starting port number', 1]),
			OptPort.new('PORTSTOP', [true, 'The stopping port number', 10000]),
			OptInt.new('TIMEOUT', [true, "The socket connect timeout in milliseconds", 1000]),
		], self.class)
		
		deregister_options('RPORT')

	end

	
	def run_host(ip)
	
		port_start = datastore['PORTSTART'].to_i
		port_stop  = datastore['PORTSTOP'].to_i
		timeout    = datastore['TIMEOUT'].to_i
		
		if(port_stop < port_start)
			tmp = port_start
			port_start = port_stop
			port_stop  = tmp
		end
	
		port_start.upto(port_stop) do |port|

			begin
				s = connect(false,
					{
						'RPORT' => port,
						'RHOST' => ip,
						'ConnectTimeout' => (timeout / 1000.0)
					}
				)
				print_status(" TCP OPEN #{ip}:#{port}")
				s.close
			rescue ::Interrupt
				raise $!
			rescue ::Errno::EINVAL
				raise $!
			rescue ::Rex::HostUnreachable
				break
			rescue ::SocketError
			rescue ::Rex::ConnectionRefused, ::Rex::ConnectionTimeout
			rescue ::Exception => e
				print_status("Unknown error: #{e.class} #{e.to_s}")
			end
		end
	end



end