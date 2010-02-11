##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Telnet
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'Telnet Service Banner Detection',
			'Version'     => '$Revision$',
			'Description' => 'Detect telnet services',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)
	end

	def run_host(ip)
		begin
			res = connect
			# This makes db_services look a lot nicer.
			banner_santized = banner.to_s.gsub(/[\x00-\x19\x7f-\xff]/) { |s| "\\x%02x" % s[0].ord}
			print_status("#{ip}:#{rport} TELNET #{banner_santized}")
			report_service(:host => rhost, :port => rport, :name => "telnet", :info => banner_santized)
		rescue ::Rex::ConnectionError
		rescue ::Exception => e
			print_error("#{e} #{e.backtrace}")
		end
	end
end

