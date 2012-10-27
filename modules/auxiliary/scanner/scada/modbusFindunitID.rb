##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##


## MODBUS/TCP  scanner to find correct Unit_ID/StationID

require 'msf/core'
class Metasploit3 < Msf::Auxiliary
	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Fuzzer

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Modbus_findunitID',
			'Description'    => %q{
				This module sends a command (0x04, read input register) to modbus endpoint.
				If this command is sent to the correct unit-id, it returns with the same funcion-id.
				if not, it should be added 0x80, so that it sys 0x84, and an exception-code follows
				which do not interest us.  This does not always happen, but at least the first 4 bytes
				in the return-packet should be exact the same as what was sent.
				You can change port, ip and the scan-range for unit-id.
				There is also added a value - BENICE - to make the scanner sleep a second or more
				between probes. We have seen installations where scanning too many too fast workes like a DoS.
			},
			'References'  =>
				[
					[ 'URL', 'http://www.saia-pcd.com/en/products/plc/pcd-overview/Pages/pcd1-m2.aspx' ],
					[ 'URL', 'http://en.wikipedia.org/wiki/Modbus:TCP' ]
				],
			'Author'         => [ 'EsMnemon <esm[at]mnemonic.no>' ],
			'License'        => MSF_LICENSE,
			'DisclosureDate' => 'Oct 28 2012',
			'Version'        => '$Revision: 0001 $'
		))
		register_options(
			[
				Opt::RPORT(502),
				OptInt.new('UNIT_ID_FROM', [true, "ModBus Unit Identifier scan from value [1..254]", 1]),
				OptInt.new('UNIT_ID_TO', [true, "ModBus Unit Identifier scan to value [UNIT_ID_FROM..254]", 254]),
				OptInt.new('BENICE', [true, "Seconds to sleep between StationID-probes, just for beeing nice", 1]),
				OptInt.new('TIMEOUT', [true, 'Timeout for the network probe, 0 means no timeout', 2])
			], self.class)
	end
	def run
	start="\x21\x00\x00\x00\x00\x06"
	theend="\x04\x00\x01\x00\x00"
	noll="\x00"
	# between, \01..\0fe  (1-254)
	if  datastore['UNIT_ID_FROM'] < 1 then
		print_status("unit ID must be between 1 and 254 adjust to 1")
		datastore['UNIT_ID_FROM']=1
	end
	if  datastore['UNIT_ID_FROM'] > 254 then
		print_status("unit ID must be between 1 and 254 adjust to 1")
		datastore['UNIT_ID_FROM']=1
	end
	if  datastore['UNIT_ID_TO'] < 1 then
		print_status("unit ID must be between 1 and 254, adjusing to #{datastore['UNIT_ID_FROM']+1} ")
		datastore['UNIT_ID_TO']=datastore['UNIT_ID_FROM'] + 1
	end
	if  datastore['UNIT_ID_TO'] > 254 then
		print_status("unit ID must be between 1 and 254, adjusing to #{datastore['UNIT_ID_FROM']+1} ")
		datastore['UNIT_ID_TO']=datastore['UNIT_ID_FROM'] + 1
	end
	if datastore['UNIT_ID_FROM'] > datastore['UNIT_ID_TO'] then
		print_status("UNIT_ID_TO is less than UNIT_ID_FROM, setting them equal")
		datastore['UNIT_ID_TO']=datastore['UNIT_ID_FROM']
	end

	counter=datastore['UNIT_ID_FROM']
	while counter <= datastore['UNIT_ID_TO']
		sploit=start
		sploit+=[counter].pack("C")
		sploit+=theend
		#sleep(datastore['BENICE'])
		select(nil,nil,nil,datastore['BENICE'])
		connect()
		sock.put(sploit)
		#debug:  print_status("sent to unit_id #{counter} ")
		data = sock.get_once(12, datastore['TIMEOUT'])
		if (data.nil?)
			data=noll+noll+noll+noll
		end
		if data[0,4]  == "\x21\x00\x00\x00"  #return of the same trans-id+proto-id
			print_good("Received: correct MODBUS/TCP from stationID  #{counter}")
		else
			print_error("Received: incorrect/none data from stationID #{counter} (probably not in use)")
		end
		disconnect()
		counter=counter + 1
	end
	end
end


=begin
  
   Modbus is a cleartext protocol used in common SCADA systems, developed
   originally as a serial-line (RS232) async protocol, and later transformed
   to IP, which is called ModbusTCP. default tcpport is 502.
  
   This client is developed and tested against a SAIA PCD1.M2 system
   http://www.saia-pcd.com/en/products/plc/pcd-overview/Pages/pcd1-m2.aspx
   and a modbus/tcp PLC simulator from plcsimulator.org
   and the Modbus SLAVE from http://www.modbustools.com/
  
   Mission is to find Unit-ID/stationID of the modbus-endpoint,
   RHOST=IP of the modbus-service (PLC)
   RPORT=Usually 502

=end
