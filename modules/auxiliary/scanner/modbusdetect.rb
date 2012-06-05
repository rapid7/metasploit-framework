## MODBUS/TCP scanner/detector
## Modbus is a cleartext protocol used in common SCADA systems, developed
## originally as a serial-line (RS232) async protocol, and later transformed
## to IP, which is called ModbusTCP. default tcpport is 502.
##
## This scanner is developed and tested on a SAIA PCD1.M2 system
## http://www.saia-pcd.com/en/products/plc/pcd-overview/Pages/pcd1-m2.aspx
##
## Theory: Whene sending a modbus request of some sort, the endpoint will
##         return with at least the same transaction-id, and protocol-id
##
##
require 'msf/core'
class Metasploit3 < Msf::Auxiliary
	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	def initialize
		super(
			'Name'        => 'Modbus Version Scanner',
			'Version'     => '$Revision: 0002 $',
			'Description' => 'Detect Modbus service .',
			'References'  =>
				[
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
	sploit="\x21\x00\x00\x00\x00\x06\x01\x04\x00\x01\x00\x00"  #read input register=func:04, register 1
	connect()
	sock.put(sploit)
	data = sock.recv(12)
	if data[0]+data[1]+data[2]+data[3]  == "\x21\x00\x00\x00"  #return of the same trans-id+proto-id
		print_status("Received: correct MODBUS/TCP header from #{ip}")
	else
		print_status("Received: incorrect data from #{ip} (not modbus/tcp?)")
	end
	disconnect()
	end
end
