##
# $Id:
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'		=> 'X11 No-Auth Scanner',
			'Version'	=> '1',
			'Description'	=> %q{
				This module scans for X11 servers that allow anyone
				to connect without authentication.
			},
			'Author'	=>
				['tebo <tebodell[at]gmail.com>'],
			'References'	=>
				[
					['OSVDB', '309'],
					['CVE', '1999-0526'],
				],
			'License'	=> MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(6000)
			],
			self.class
		)

	end

	def run_host(ip)

		begin

			print_status("Trying #{ip}")

			connect

			# X11.00 Null Auth Connect
			buf =   "\x6c\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00"

			sock.put(buf)
			response = sock.get_once
			
			if response
				success = response[0]
			end

			if success == 1
				vendor_len = response[24..25].unpack('s')[0]
				vendor = response[40..(40+vendor_len)].unpack('A*')
				
				print_status("Open X Server @ #{ip} (#{vendor})")
			elsif success == 0
				print_status("Access Denied on #{ip}")
			else
				# X can return a reason for auth failure but we don't really care for this
			end

		rescue ::Rex::ConnectionError
		rescue ::Errno::EPIPE

		end

	end

end
