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
			'Author'      => [ 'hdm', 'Kris Katterjohn <katterjohn[at]gmail.com>' ],
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
		ports = []

		# Build ports array from port specification
		datastore['PORTS'].split(/,/).each do |item|
			start, stop = item.split(/-/).map { |p| p.to_i }

			start ||= 0
			stop ||= item.match(/-/) ? 65535 : start

			start, stop = stop, start if stop < start

			start.upto(stop) { |p| ports << p }
		end

		# Sort, and remove dups and invalid ports
		ports = ports.sort.uniq.delete_if { |p| p < 0 or p > 65535 }

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
				s.close
			rescue ::Interrupt
				raise $!
			rescue ::Errno::EINVAL
				raise $!
			rescue ::Rex::HostUnreachable
				break
			rescue ::SocketError
			rescue ::Rex::ConnectionRefused, ::Rex::ConnectionTimeout
			rescue ::Errno::EACCES
			rescue ::Exception => e
				print_status("Unknown error: #{e.class} #{e.to_s}")
			end
		end
	end



end
