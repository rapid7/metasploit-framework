##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Capture

  def initialize
    super(
      'Name'         => 'BNAT Scanner',
      'Description'  => %q{
          This module is a scanner which can detect Broken NAT (network address translation)
        implementations, which could result in an inability to reach ports on remote
        machines. Typically, these ports will appear in nmap scans as 'filtered'/'closed'.
        },
      'Author'       =>
        [
          'bannedit',
          'Jonathan Claudius <jclaudius[at]trustwave.com>',
        ],
      'License'      => MSF_LICENSE,
      'References'   =>
        [
          [ 'URL', 'https://github.com/claudijd/bnat'],
          [ 'URL', 'http://www.slideshare.net/claudijd/dc-skytalk-bnat-hijacking-repairing-broken-communication-channels']
        ]
    )

    register_options(
        [
          OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "21,22,23,80,443"]),
          OptString.new('INTERFACE', [true, "The name of the interface", "eth0"]),
          OptInt.new('TIMEOUT', [true, "The reply read timeout in milliseconds", 500])
        ])

    deregister_options('FILTER','PCAPFILE','SNAPLEN')

  end

  def probe_reply(pcap, to)
    reply = nil
    begin
      Timeout.timeout(to) do
        pcap.each do |r|
          pkt = PacketFu::Packet.parse(r)
          next unless pkt.is_tcp?
          reply = pkt
          break
        end
      end
      rescue Timeout::Error
    end
    return reply
  end

  def generate_probe(ip)
    ftypes = %w{windows, linux, freebsd}
    @flavor = ftypes[rand(ftypes.length)]
    config = PacketFu::Utils.whoami?(:iface => datastore['INTERFACE'])
    p = PacketFu::TCPPacket.new(:config => config)
    p.ip_daddr = ip
    p.tcp_flags.syn = 1
    return p
  end

  def run_host(ip)
    open_pcap

    to = (datastore['TIMEOUT'] || 500).to_f / 1000.0

    p = generate_probe(ip)
    pcap = self.capture

    ports = Rex::Socket.portspec_crack(datastore['PORTS'])

    if ports.empty?
      raise Msf::OptionValidateError.new(['PORTS'])
    end

    ports.each_with_index do |port,i|
      p.tcp_dst = port
      p.tcp_src = rand(64511)+1024
      p.tcp_seq = rand(64511)+1024
      p.recalc

      ackbpf = "tcp [8:4] == 0x#{(p.tcp_seq + 1).to_s(16)}"
      pcap.setfilter("tcp and tcp[13] == 18 and not host #{ip} and src port #{p.tcp_dst} and dst port #{p.tcp_src} and #{ackbpf}")
      break unless capture_sendto(p, ip)
      reply = probe_reply(pcap, to)
      next if reply.nil?

      print_status("[BNAT RESPONSE] Requested IP: #{ip} Responding IP: #{reply.ip_saddr} Port: #{reply.tcp_src}")
    end

    close_pcap
  end
end
