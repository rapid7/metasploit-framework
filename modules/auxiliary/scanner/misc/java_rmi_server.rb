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

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'Java RMI Server Endpoint Scanner',
			'Version'     => '$Revision$',
			'Description' => 'Detect Java RMI endpoints',
			'Authors'     => ['mihi', 'hdm'],
			'License'     => MSF_LICENSE,
			'References'     =>
				[
					# RMI protocol specification
					[ 'URL', 'http://download.oracle.com/javase/1.3/docs/guide/rmi/spec/rmi-protocol.html'],
				],
			'DisclosureDate' => 'Oct 15 2011',			
		)

		register_options(
			[
				Opt::RPORT(1099),
			], self.class)
	end

	def run_host(target_host)

		begin
			connect
			sock.put("\x4a\x52\x4d\x49\0\x02\x4b")
			res = sock.get_once

			if res and res =~ /^\x4e..([^\x00]+)\x00\x00/
				info = $1
				print_good("#{rhost}:#{rport} Java RMI Endpoint Detected (identified us as '#{info}')")
				report_service(:host => rhost, :port => rport, :name => "rmi", :info => "Java RMI Endpoint (identified us as #{info})")
				report_vuln(
					:host          => rhost,
					:name          => self.fullname,
					:port          => rport,
					:info          => "Identified Java RMI Endpoint",
					:refs          => self.references
				)				
			end
			
		rescue ::Interrupt
			raise $!
		rescue ::Rex::ConnectionError, ::IOError
		ensure
			disconnect
		end

	end
end
