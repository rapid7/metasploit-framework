##
# This module requires Metasploit: http://metasploit.com/download
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
          ['WRITE_REGISTER', { 'Description' => 'Write one word to a register' } ]
        ],
      'DefaultAction' => 'READ_REGISTER'
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
    sock.get_once(-1, sock.def_read_timeout)
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
    make_payload(payload)
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
    payload = [datastore['UNIT_NUMBER']].pack("c")
    payload += [@function_code].pack("c")
    payload += [datastore['DATA_ADDRESS']].pack("n")
    payload += [data].pack("n")

    make_payload(payload)
  end

  def handle_error(response)
    case response.reverse.unpack("c")[0].to_i
    when 1
      print_error("Error : ILLEGAL FUNCTION")
    when 2
      print_error("Error : ILLEGAL DATA ADDRESS")
    when 3
      print_error("Error : ILLEGAL DATA VALUE")
    when 4
      print_error("Error : SLAVE DEVICE FAILURE")
    when 6
      print_error("Error : SLAVE DEVICE BUSY")
    else
      print_error("Unknown error")
    end
    return
  end

  def read_coil
    @function_code = 0x1
    print_status("Sending READ COIL...")
    response = send_frame(make_read_payload)
    if response.nil?
      print_error("No answer for the READ COIL")
      return
    elsif response.unpack("C*")[7] == (0x80 | @function_code)
      handle_error(response)
    elsif response.unpack("C*")[7] == @function_code
      value = response[9].unpack("c")[0]
      print_good("Coil value at address #{datastore['DATA_ADDRESS']} : #{value}")
    else
      print_error("Unknown answer")
    end
  end

  def read_register
    @function_code = 3
    print_status("Sending READ REGISTER...")
    response = send_frame(make_read_payload)
    if response.nil?
      print_error("No answer for the READ REGISTER")
    elsif response.unpack("C*")[7] == (0x80 | @function_code)
      handle_error(response)
    elsif response.unpack("C*")[7] == @function_code
      value = response[9..10].unpack("n")[0]
      print_good("Register value at address #{datastore['DATA_ADDRESS']} : #{value}")
    else
      print_error("Unknown answer")
    end
  end

  def write_coil
    @function_code = 5
    if datastore['DATA'] == 0
      data = 0
    elsif datastore['DATA'] == 1
      data = 255
    else
      print_error("Data value must be 0 or 1 in WRITE_COIL mode")
      return
    end
    print_status("Sending WRITE COIL...")
    response = send_frame(make_write_coil_payload(data))
    if response.nil?
      print_error("No answer for the WRITE COIL")
    elsif response.unpack("C*")[7] == (0x80 | @function_code)
      handle_error(response)
    elsif response.unpack("C*")[7] == @function_code
      print_good("Value #{datastore['DATA']} successfully written at coil address #{datastore['DATA_ADDRESS']}")
    else
      print_error("Unknown answer")
    end
  end

  def write_register
    @function_code = 6
    if datastore['DATA'] < 0 || datastore['DATA'] > 65535
      print_error("Data to write must be an integer between 0 and 65535 in WRITE_REGISTER mode")
      return
    end
    print_status("Sending WRITE REGISTER...")
    response = send_frame(make_write_register_payload(datastore['DATA']))
    if response.nil?
      print_error("No answer for the WRITE REGISTER")
    elsif response.unpack("C*")[7] == (0x80 | @function_code)
      handle_error(response)
    elsif response.unpack("C*")[7] == @function_code
      print_good("Value #{datastore['DATA']} successfully written at registry address #{datastore['DATA_ADDRESS']}")
    else
      print_error("Unknown answer")
    end
  end

  def run
    @modbus_counter = 0x0000 # used for modbus frames
    connect
    case action.name
    when "READ_COIL"
      read_coil
    when "READ_REGISTER"
      read_register
    when "WRITE_COIL"
      write_coil
    when "WRITE_REGISTER"
      write_register
    else
      print_error("Invalid ACTION")
    end
    disconnect
  end
end
