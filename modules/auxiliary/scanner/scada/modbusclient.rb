##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Rex::Socket::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Modbus client, reloaded.',
      'Description'   => %q{
        This module allows reading and writing data to a PLC using the Modbus protocol.

        This module is based on the 'modiconstop.rb' Basecamp module from
        DigitalBond, as well as the mbtget perl script.
      },
      'Author'         =>
        [
          'EsMnemon <esm [at] mnemonic.no>', # original write-only module
          'Arnaud SOULLIE  <arnaud.soullie[at]solucom.fr>', # new code that allows read/write
        ],
      'License'        => MSF_LICENSE,
      ))
    register_options(
      [
        OptEnum.new("MODE", [true, 'Command', "READ_REGISTER",
          [
            "READ_REGISTER",
            "READ_COIL",
            "WRITE_REGISTER",
            "WRITE_COIL"
          ]
        ]),
        Opt::RPORT(502),
        OptInt.new('DATA', [false, "Data to write (WRITE_COIL and WRITE_REGISTER modes only)", 0xBEEF]),
        OptInt.new('DATA_ADDRESS', [true, "Modbus data address", 0]),
        OptInt.new('UNIT_NUMBER', [false, "Modbus unit number (255 if not used)", 255]),
      ], self.class)

  end

  # Don't mess with live production SCADA systems
  def scada_write_warning
    print_status("Warning : do not try to alter live SCADA configuration. Bad shit can happened. Continue ? (y/n)")
    go_on = gets
    unless go_on.chomp == 'y'
      print_error("Stopping module")
      exit
    end
  end

  # a wrapper just to be sure we increment the counter
  def sendframe(payload)
    sock.put(payload)
    @modbuscounter += 1
    r = sock.recv(65535, 0.1)
    return r
  end

  def make_read_payload
    payload = ""
    payload += [datastore['UNIT_NUMBER']].pack("c")
    payload += [@function_code].pack("c")
    payload += [datastore['DATA_ADDRESS']].pack("n")
    payload += [1].pack("n")

    packetdata = ""
    packetdata += [@modbuscounter].pack("n")
    packetdata += "\x00\x00\x00" #dunno what these are
    packetdata += [payload.size].pack("c") # size byte
    packetdata += payload

    return packetdata
  end

  def make_write_coil_payload(data)
    payload = ""
    payload += [datastore['UNIT_NUMBER']].pack("c")
    payload += [@function_code].pack("c")
    payload += [datastore['DATA_ADDRESS']].pack("n")
    payload += [data].pack("c")
    payload += "\x00"

    packetdata = ""
    packetdata += [@modbuscounter].pack("n")
    packetdata += "\x00\x00\x00" #dunno what these are
    packetdata += [payload.size].pack("c") # size byte
    packetdata += payload

    return packetdata
  end

    def make_write_register_payload(data)
    payload = ""
    payload += [datastore['UNIT_NUMBER']].pack("c")
    payload += [@function_code].pack("c")
    payload += [datastore['DATA_ADDRESS']].pack("n")
    payload += [data].pack("n")

    packetdata = ""
    packetdata += [@modbuscounter].pack("n")
    packetdata += "\x00\x00\x00" #dunno what these are
    packetdata += [payload.size].pack("c") # size byte
    packetdata += payload

    return packetdata
  end

  def run
    @modbuscounter = 0x0000 # used for modbus frames
    connect
    case datastore['MODE']
    when "READ_COIL"
      @function_code = 1
      response = sendframe(make_read_payload)
      print_good("Coil value at address #{datastore['DATA_ADDRESS']} : " + response.reverse.unpack("c").to_s.gsub('[', '').gsub(']', ''))

    when "READ_REGISTER"
      @function_code = 3
      response = sendframe(make_read_payload)
      value = response.split[0][9..10].to_s.unpack("n").to_s.gsub('[', '').gsub(']','')
      print_good("Register value at address #{datastore['DATA_ADDRESS']} : " + value)

    when "WRITE_COIL"
      scada_write_warning
      @function_code = 5
      if datastore['DATA'] == 0
        data = 0
      elsif datastore['DATA'] == 1
        data = 255
      else
        print_error("Data value must be 0 or 1 in WRITE_COIL mode")
        exit
      end
      response = sendframe(make_write_coil_payload(data))
      print_good("Value #{datastore['DATA']} successfully written at coil address #{datastore['DATA_ADDRESS']}")

    when "WRITE_REGISTER"
      scada_write_warning
      @function_code = 6
      if datastore['DATA'] < 0 || datastore['DATA'] > 65535
        print_error("Data to write must be an integer between 0 and 65535 in WRITE_REGISTER mode")
        exit
      end
      response = sendframe(make_write_register_payload(datastore['DATA']))
      print_good("Value #{datastore['DATA']} successfully written at registry address #{datastore['DATA_ADDRESS']}")

    else
      print_error("Invalid MODE")
      return
    end
  end
end