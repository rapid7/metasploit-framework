##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Modbus Client Utility',
      'Description'   => %q{
        This module allows reading and writing data to a PLC using the Modbus protocol.
        This module is based on the 'modiconstop.rb' Basecamp module from DigitalBond,
        as well as the mbtget perl script.
      },
      'Author'         =>
        [
          'EsMnemon <esm[at]mnemonic.no>', # original write-only module
          'Arnaud SOULLIE  <arnaud.soullie[at]solucom.fr>' # new code that allows read/write
        ],
      'License'        => MSF_LICENSE,
      'Actions'        =>
        [
          ['READ_COIL', { 'Description' => 'Read one bit from a coil' } ],
          ['WRITE_COIL', { 'Description' => 'Write one bit to a coil' } ],
          ['READ_REGISTER', { 'Description' => 'Read one word from a register' } ],
          ['WRITE_REGISTER', { 'Description' => 'Write one word to a register' } ],
        ]
      ))

    register_options(
      [
        Opt::RPORT(502),
        OptInt.new('DATA', [false, "Data to write (WRITE_COIL and WRITE_REGISTER modes only)"]),
        OptInt.new('DATA_ADDRESS', [true, "Modbus data address"]),
        OptInt.new('UNIT_NUMBER', [false, "Modbus unit number", 1]),
      ], self.class)

  end

  # a wrapper just to be sure we increment the counter
  def send_frame(payload)
    sock.put(payload)
    @modbus_counter += 1
    r = sock.get
    return r
  end

  def make_payload(payload)
    packet_data = [@modbus_counter].pack("n")
    packet_data += "\x00\x00\x00" #dunno what these are
    packet_data += [payload.size].pack("c") # size byte
    packet_data += payload

    packet_data
  end

  def make_read_payload
    payload = [datastore['UNIT_NUMBER']].pack("c")
    payload += [@function_code].pack("c")
    payload += [datastore['DATA_ADDRESS']].pack("n")
    payload += [1].pack("n")

    packet_data = make_payload(payload)

    packet_data
  end

  def make_write_coil_payload(data)
    payload = [datastore['UNIT_NUMBER']].pack("c")
    payload += [@function_code].pack("c")
    payload += [datastore['DATA_ADDRESS']].pack("n")
    payload += [data].pack("c")
    payload += "\x00"

    packet_data = make_payload(payload)

    packet_data
  end

    def make_write_register_payload(data)
    payload = ""
    payload += [datastore['UNIT_NUMBER']].pack("c")
    payload += [@function_code].pack("c")
    payload += [datastore['DATA_ADDRESS']].pack("n")
    payload += [data].pack("n")

    packet_data = make_payload(payload)

    packet_data
  end

  def run
    @modbus_counter = 0x0000 # used for modbus frames
    connect
    case datastore['ACTION']
    when "READ_COIL"
      @function_code = 1
      response = send_frame(make_read_payload)
      print_good("Coil value at address #{datastore['DATA_ADDRESS']} : " + response.reverse.unpack("c").to_s.gsub('[', '').gsub(']', ''))
    when "READ_REGISTER"
      @function_code = 3
      response = send_frame(make_read_payload)
      value = response.split[0][9..10].to_s.unpack("n").to_s.gsub('[', '').gsub(']','')
      print_good("Register value at address #{datastore['DATA_ADDRESS']} : " + value)
    when "WRITE_COIL"
      @function_code = 5
      if datastore['DATA'] == 0
        data = 0
      elsif datastore['DATA'] == 1
        data = 255
      else
        print_error("Data value must be 0 or 1 in WRITE_COIL mode")
        exit
      end
      response = send_frame(make_write_coil_payload(data))
      print_good("Value #{datastore['DATA']} successfully written at coil address #{datastore['DATA_ADDRESS']}")
    when "WRITE_REGISTER"
      @function_code = 6
      if datastore['DATA'] < 0 || datastore['DATA'] > 65535
        print_error("Data to write must be an integer between 0 and 65535 in WRITE_REGISTER mode")
        exit
      end
      response = send_frame(make_write_register_payload(datastore['DATA']))
      print_good("Value #{datastore['DATA']} successfully written at registry address #{datastore['DATA_ADDRESS']}")
    else
      print_error("Invalid ACTION")
    end

    disconnect
  end
end