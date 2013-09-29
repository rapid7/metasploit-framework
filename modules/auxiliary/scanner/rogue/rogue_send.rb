##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Rogue Gateway Detection: Sender',
            'Description' => %q{
              This module send a series of TCP SYN and ICMP ECHO requests
              to each internal target host, spoofing the source address of an external
              system running the rogue_recv module. This allows the system running
              the rogue_recv module to determine what external IP a given internal
              system is using as its default route.
            },
            'Author'      => 'hdm',
            'License'     => MSF_LICENSE,
            'References'  =>
                [
                    ['URL', 'http://www.metasploit.com/research/projects/rogue_network/'],
                ]
        )
    )

    register_options([
      OptAddress.new("EHOST", [true, "The IP address of the machine running rogue_recv"]),
      OptPort.new("RPORT", [true, "The destination port for the TCP SYN packet", 80]),
      OptPort.new("CPORT", [true, "The source port for the TCP SYN packet", 13832]),
      OptInt.new("ECHOID", [true, "The unique ICMP ECHO ID to embed into the packet", 7893]),
    ])

    deregister_options('FILTER','PCAPFILE')
  end

  def run_host(ip)
    open_pcap

    pcap = self.capture

    capture_sendto(build_tcp_syn(ip), ip)

    capture_sendto(build_icmp(ip), ip)

    close_pcap
  end

  def build_tcp_syn(dst)
    p = PacketFu::TCPPacket.new
    p.ip_saddr = datastore['EHOST']
    p.ip_daddr = dst
    p.ip_ttl = 255
    p.tcp_sport = datastore['CPORT'].to_i
    p.tcp_dport = datastore['RPORT'].to_i
    p.tcp_flags.syn = 1
    p.tcp_seq = Rex::Socket.addr_atoi(dst)
    p.recalc
    p
  end

  def build_icmp(dst)
    p = PacketFu::ICMPPacket.new
    p.ip_saddr = datastore['EHOST']
    p.ip_daddr = dst
    p.ip_ttl = 255
    p.icmp_type = 8
    payload = Rex::Socket.addr_aton(dst) + [datastore['ECHOID']].pack('n') + Rex::Text.rand_text(26)
    p.payload = capture_icmp_echo_pack(datastore['ECHOID'],1,payload)
    p.recalc
  end
end
