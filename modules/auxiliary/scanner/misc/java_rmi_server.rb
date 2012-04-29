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
					# Placeholder reference for matching
					[ 'MSF', 'java_rmi_server']
				],
			'DisclosureDate' => 'Oct 15 2011'
		)

		register_options(
			[
				Opt::RPORT(1099)
			], self.class)
	end
	
	def setup
		@pkt = "JRMI" + [2,0x4b,0,0].pack("nCnN") + gen_rmi_loader_packet
	end

	def run_host(target_host)

		begin
			connect
			sock.put("\x4a\x52\x4d\x49\0\x02\x4b")
			res = sock.get_once

			if res and res =~ /^\x4e..([^\x00]+)\x00\x00/
				info = $1

				# Determine if the instance allows remote class loading
				sock.put(@pkt)
	
				buf = ""
				1.upto(6) do
					res = sock.get_once(-1, 5) rescue nil
					break if not res
					buf << res
				end

				if buf =~ /RMI class loader disabled/
					print_status("#{rhost}:#{rport} Java RMI Endpoint Detected")
					report_service(:host => rhost, :port => rport, :name => "java-rmi", :info => "Class Loader: Disabled")
				else
					print_good("#{rhost}:#{rport} Java RMI Endpoint Detected: Class Loader Enabled")
					report_service(:host => rhost, :port => rport, :name => "java-rmi", :info => "Class Loader: Enabled")
					report_vuln(
						:host         => rhost,
						:port         => rport,
						:proto        => 'tcp',
						:sname => (ssl ? 'https' : 'http'),
						:name         => self.fullname,
						:info         => "Class Loader: Enabled",
						:refs         => self.references
					)
				end

			end

		rescue ::Interrupt
			raise $!
		rescue ::Rex::ConnectionError, ::IOError
		ensure
			disconnect
		end

	end
	
	def gen_rmi_loader_packet
		"\x50\xac\xed\x00\x05\x77\x22\x00\x00\x00\x00\x00\x00\x00\x02\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\xf6\xb6\x89\x8d\x8b\xf2\x86\x43\x75\x72\x00\x18\x5b\x4c\x6a" +
		"\x61\x76\x61\x2e\x72\x6d\x69\x2e\x73\x65\x72\x76\x65\x72\x2e\x4f" +
		"\x62\x6a\x49\x44\x3b\x87\x13\x00\xb8\xd0\x2c\x64\x7e\x02\x00\x00" +
		"\x70\x78\x70\x00\x00\x00\x00\x77\x08\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x73\x72\x00\x14\x6d\x65\x74\x61\x73\x70\x6c\x6f\x69\x74\x2e" +
		"\x52\x4d\x49\x4c\x6f\x61\x64\x65\x72\xa1\x65\x44\xba\x26\xf9\xc2" +
		"\xf4\x02\x00\x00\x74\x00\x13\x66\x69\x6c\x65\x3a\x2e\x2f\x72\x6d" +
		"\x69\x64\x75\x6d\x6d\x79\x2e\x6a\x61\x72\x78\x70\x77\x01\x00\x0a"
	end	
	
	
end
