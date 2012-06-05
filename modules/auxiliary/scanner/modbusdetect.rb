##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Modbus Version Scanner',
			'Version'     => '$Revision: 0002 $',
			'Description' => %q{
					This module detects the Modbus service, tested on a SAIA PCD1.M2 system.
				Modbus is a cleartext protocol used in common SCADA systems, developed
				originally as a serial-line (RS232) async protocol, and later transformed to IP,
				which is called ModbusTCP. The default tcpport is 502.
			},
			'References'  =>
				[
					[ 'URL', 'http://www.saia-pcd.com/en/products/plc/pcd-overview/Pages/pcd1-m2.aspx' ],
					[ 'URL', 'http://en.wikipedia.org/wiki/Modbus:TCP' ],
				],
			'Author'      => [ 'EsMnemon <esm[at]mnemonic.no>' ],
			'DisclosureDate' => 'Nov 1 2011',
			'License'     => MSF_LICENSE
			)

		register_options(
			[
				Opt::RPORT(502),
				OptInt.new('TIMEOUT', [true, 'Timeout for the network probe', 10])
			], self.class)
	end

	def run_host(ip)
		#read input register=func:04, register 1
		sploit="\x21\x00\x00\x00\x00\x06\x01\x04\x00\x01\x00\x00"
		connect()
		sock.put(sploit)
		data = sock.recv(12)

		# Theory: Whene sending a modbus request of some sort, the endpoint will return
		# with at least the same transaction-id, and protocol-id
		if data[0,4] == "\x21\x00\x00\x00"
			print_status("Received: correct MODBUS/TCP header from #{ip}")
		else
			print_status("Received: incorrect data from #{ip} (not modbus/tcp?)")
		end

		disconnect()
	end
end
