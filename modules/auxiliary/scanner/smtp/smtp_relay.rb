##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
# http://metasploit.com/
##
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Smtp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'SMTP Open Relay Detection',
			'Description' => 'SMTP Open Relay Detection',
			'References'  =>
				[
			['URL', 'http://www.ietf.org/rfc/rfc2821.txt'],
				],
			'Author'      => 'Campbell Murray',
			'License'     => MSF_LICENSE
		)
	end

	def run_host(ip)
		connect
		banner_sanitized = Rex::Text.to_hex_ascii(banner.to_s)
		print_status("#{ip}:#{rport} SMTP #{banner_sanitized}")
		report_service(:host => rhost, :port => rport, :name => "smtp", :info => banner)
		do_test_relay()
	end	

	def do_test_relay
		raw_send_recv("EHLO X\r\n")
		raw_send_recv("MAIL FROM: #{datastore['MAILFROM']}\r\n") 
		raw_send_recv("RCPT TO: #{datastore['MAILTO']}\r\n") 
		raw_send_recv("DATA\r\n") 
		raw_send_recv("Metasploit testing for open relay\r\n") 
		res=raw_send_recv(".\r\n") 
		  if res =~ /250/ 
		    print_good "Potential open SMTP relay detected at #{rhost.to_s}"
		  else
		    print_status "Not vulnerable"
		  end
	end
end