##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Smtp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'SMTP Banner Grabber',
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

	def run_host(ip)
		res = connect
		banner_sanitized = Rex::Text.to_hex_ascii(banner.to_s)
		print_status("#{ip}:#{rport} SMTP #{banner_sanitized}")
		report_service(:host => rhost, :port => rport, :name => "smtp", :info => banner)
	end

end
