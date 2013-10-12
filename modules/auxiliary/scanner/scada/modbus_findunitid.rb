##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Fuzzer

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Modbus Unit ID and Station ID Enumerator',
      'Description'    => %q{
        Modbus is a cleartext protocol used in common SCADA systems, developed
        originally as a serial-line (RS232) async protocol, and later transformed
        to IP, which is called ModbusTCP. default tcpport is 502.

        This module sends a command (0x04, read input register) to the modbus endpoint.
        If this command is sent to the correct unit-id, it returns with the same funcion-id.
        if not, it should be added 0x80, so that it sys 0x84, and an exception-code follows
        which do not interest us. This does not always happen, but at least the first 4
        bytes in the return-packet should be exact the same as what was sent.

        You can change port, ip and the scan-range for unit-id. There is also added a
        value - BENICE - to make the scanner sleep a second or more between probes. We
        have seen installations where scanning too many too fast works like a DoS.
      },
      'References'  =>
        [
          [ 'URL', 'http://www.saia-pcd.com/en/products/plc/pcd-overview/Pages/pcd1-m2.aspx' ],
          [ 'URL', 'http://en.wikipedia.org/wiki/Modbus:TCP' ]
        ],
      'Author'         => [ 'EsMnemon <esm[at]mnemonic.no>' ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Oct 28 2012'
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
    # between, \01..\0ff  (1-255)
    unless (1..255).include? datastore['UNIT_ID_FROM']
      print_status("unit ID must be between 1 and 254 adjusting  UNIT_ID_FROM to 1")
      datastore['UNIT_ID_FROM']=1
    end

    unless (1..255).include? datastore['UNIT_ID_TO']
      print_status("Unit ID must be between #{datastore['UNIT_ID_FROM']} and 255")
      print_warning("Adjusting UNIT_ID_TO to #{datastore['UNIT_ID_FROM']} ")
      datastore['UNIT_ID_TO'] = datastore['UNIT_ID_FROM']
    end

    if datastore['UNIT_ID_FROM'] > datastore['UNIT_ID_TO'] then
      print_warning("UNIT_ID_TO is less than UNIT_ID_FROM, setting them equal")
      datastore['UNIT_ID_TO'] = datastore['UNIT_ID_FROM']
    end

    datastore['UNIT_ID_FROM'].upto(datastore['UNIT_ID_TO']) do |counter|
      sploit  = start
      sploit += [counter].pack("C")
      sploit += theend
      Rex.sleep(datastore['BENICE'])
      connect()
      sock.put(sploit)

      data = sock.get_once(12, datastore['TIMEOUT'])
      if (data.nil?)
        data=noll+noll+noll+noll
      end

      if data[0,4]  == "\x21\x00\x00\x00"  #return of the same trans-id+proto-id
        print_good("Received: correct MODBUS/TCP from stationID  #{counter}")
      else
        print_status("Received: incorrect/none data from stationID #{counter} (probably not in use)")
      end

      disconnect()
    end
  end
end


=begin
For testing purposes:

  This client is developed and tested against a SAIA PCD1.M2 system
  http://www.saia-pcd.com/en/products/plc/pcd-overview/Pages/pcd1-m2.aspx
  and a modbus/tcp PLC simulator from plcsimulator.org
  and the Modbus SLAVE from http://www.modbustools.com/
  
  Mission is to find Unit-ID/stationID of the modbus-endpoint:
  RHOST=IP of the modbus-service (PLC)
  RPORT=Usually 502
=end
