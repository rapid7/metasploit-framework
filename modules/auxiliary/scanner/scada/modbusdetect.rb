##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Modbus Version Scanner',
      'Description' => %q{
          This module detects the Modbus service, tested on a SAIA PCD1.M2 system.
        Modbus is a clear text protocol used in common SCADA systems, developed
        originally as a serial-line (RS232) async protocol, and later transformed to IP,
        which is called ModbusTCP.
      },
      'References'  =>
        [
          [ 'URL', 'http://www.saia-pcd.com/en/products/plc/pcd-overview/Pages/pcd1-m2.aspx' ],
          [ 'URL', 'http://en.wikipedia.org/wiki/Modbus:TCP' ]
        ],
      'Author'      => [ 'EsMnemon <esm[at]mnemonic.no>' ],
      'DisclosureDate' => 'Nov 1 2011',
      'License'     => MSF_LICENSE
      )

    register_options(
      [
        Opt::RPORT(502),
        OptInt.new('UNIT_ID', [true, "ModBus Unit Identifier, 1..255, most often 1 ", 1]),
        OptInt.new('TIMEOUT', [true, 'Timeout for the network probe', 10])
      ])
  end

  def run_host(ip)
    # read input register=func:04, register 1
    sploit="\x21\x00\x00\x00\x00\x06\x01\x04\x00\x01\x00\x00"
    sploit[6] = [datastore['UNIT_ID']].pack("C")
    connect()
    sock.put(sploit)
    data = sock.get_once

    # Theory: When sending a modbus request of some sort, the endpoint will return
    # with at least the same transaction-id, and protocol-id
    if data
      if data[0,4] == "\x21\x00\x00\x00"
        print_good("#{ip}:#{rport} - MODBUS - received correct MODBUS/TCP header (unit-ID: #{datastore['UNIT_ID']})")
      else
        print_error("#{ip}:#{rport} - MODBUS - received incorrect data #{data[0,4].inspect} (not modbus/tcp?)")
      end
    else
      vprint_status("#{ip}:#{rport} - MODBUS - did not receive data.")
    end

    disconnect()
  end
end
