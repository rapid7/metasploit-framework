##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Imap
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'IMAP4 Banner Grabber',
			'Version'     => '$Revision$',
			'Description' => 'IMAP4 Banner Grabber',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)
	end

	def run_host(ip)
		begin
			res = connect
			banner_sanitized = banner.to_s.gsub(/[\x00-\x19\x7f-\xff]/) { |s| "\\x%02x" % s[0,1].unpack("C")[0] }
			print_status("#{ip}:#{rport} IMAP #{banner_sanitized}")
			report_service(:host => rhost, :port => rport, :name => "imap", :info => banner)
		rescue ::Rex::ConnectionError
		rescue ::Exception => e
			print_error("#{rhost}:#{rport} #{e} #{e.backtrace}")
		end
	end

end

