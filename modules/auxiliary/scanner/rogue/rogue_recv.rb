##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Capture

  def initialize
    super(
      'Name'        => 'Rogue Gateway Detection: Receiver',
      'Description' => %q{
        This module listens for replies to the requests sent by
      the rogue_send module. The RPORT, CPORT, and ECHOID values
      must match the rogue_send parameters used exactly.
      },
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_options([
      OptPort.new("RPORT", [true, "The destination port for the TCP SYN packet", 80]),
      OptPort.new("CPORT", [true, "The source port for the TCP SYN packet", 13832]),
      OptInt.new("ECHOID", [true, "The unique ICMP ECHO ID to embed into the packet", 7893]),
    ])
    deregister_options('RHOST')
  end

  def build_filter
    "(icmp and icmp[0] == 0) or (" +
      "tcp and (tcp[13] == 0x12 or (tcp[13] & 0x04) != 0) and " +
      "src port #{datastore['RPORT']} and dst port #{datastore['CPORT']} " +
    ")"
  end

  def run
    open_pcap('SNAPLEN' => 128, 'FILTER' => build_filter)
    print_status("Opening the capture interface...")

    print_status("Waiting for responses to rogue_send...")
    begin
    each_packet do |pkt|
      r = parse_reply(pkt)
      next if not r
      print_status("Reply from #{r[:internal]} using gateway #{r[:external]} (#{r[:type].to_s.upcase})")
    end
    rescue ::Interrupt
      raise $!
    ensure
      close_pcap
    end
  end

  def parse_reply(r)
    p = PacketFu::Packet.parse(r)
    return unless p.is_eth?
    if p.is_icmp?
      return if(p.payload[0,2] != [datastore['ECHOID']].pack("n"))
      return unless p.payload.size >= 8
      reply = {:raw => p}
      reply[:type] = :icmp
      reply[:internal] = Rex::Socket.addr_nota(p.payload[4,4])
      reply[:external] = p.ip_saddr
    elsif p.is_tcp?
      return if p.tcp_ack.zero?
      reply = {:packet => p}
      reply[:type] = :tcp
      reply[:internal] = Rex::Socket.addr_itoa(p.tcp_ack - 1)
      reply[:external] = p.ip_saddr
    else
      reply = nil
    end
    return reply
  end
end
