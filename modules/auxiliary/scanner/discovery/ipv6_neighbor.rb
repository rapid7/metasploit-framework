##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ipv6
  include Msf::Exploit::Remote::Capture
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'IPv6 Local Neighbor Discovery',
      'Description' => %q{
        Enumerate local IPv6 hosts which respond to Neighbor Solicitations with a link-local address.
        Note, that like ARP scanning, this usually cannot be performed beyond the local
        broadcast network.
    },
      'Author' => 'belch',
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options(
      [
        OptString.new('SHOST', [false, 'Source IP Address']),
        OptString.new('SMAC', [false, 'Source MAC Address']),
        OptInt.new('TIMEOUT', [true, 'The number of seconds to wait for new data', 5]),
      ]
    )

    deregister_options('SNAPLEN', 'FILTER')
  end

  def run_batch_size
    datastore['BATCHSIZE'] || 256
  end

  def run_batch(hosts)
    open_pcap({ 'SNAPLEN' => 68, 'FILTER' => 'arp[6:2] == 0x0002' })

    @netifaces = true
    if !netifaces_implemented?
      print_error('WARNING : Pcaprub is not up-to-date, some functionality will not be available')
      @netifaces = false
    end

    print_status('Discovering IPv4 nodes via ARP...')

    @interface = datastore['INTERFACE'] || Pcap.lookupdev
    @shost = datastore['SHOST']
    @shost ||= get_ipv4_addr(@interface) if @netifaces
    raise 'SHOST should be defined' unless @shost

    @smac = datastore['SMAC']
    @smac ||= get_mac(@interface) if @netifaces
    raise 'SMAC should be defined' unless @smac

    addrs = []

    begin
      found = {}
      hosts.each do |dhost|
        probe = buildprobe(@shost, @smac, dhost)
        capture.inject(probe)
        while (reply = getreply)
          next unless reply.is_arp?

          next if found[reply.arp_saddr_ip]

          print_good(sprintf('  %16s ALIVE', reply.arp_saddr_ip))
          addrs << [reply.arp_saddr_ip, reply.arp_saddr_mac]
          report_host(host: reply.arp_saddr_ip, mac: reply.arp_saddr_mac)
          found[reply.arp_saddr_ip] = true
        end
      end

      etime = ::Time.now.to_f + datastore['TIMEOUT']

      while (::Time.now.to_f < etime)
        while (reply = getreply)
          next unless reply.is_arp?

          next if found[reply.arp_saddr_ip]

          print_good(sprintf('  %16s ALIVE', reply.arp_saddr_ip))
          addrs << [reply.arp_saddr_ip, reply.arp_saddr_mac]
          report_host(host: reply.arp_saddr_ip, mac: reply.arp_saddr_mac)
          found[reply.arp_saddr_ip] = true
        end

        ::IO.select(nil, nil, nil, 0.50)
      end
    ensure
      close_pcap
    end

    neighbor_discovery(addrs)
  end

  def map_neighbor(nodes, adv)
    nodes.each do |node|
      ipv4_addr, mac_addr = node
      next unless adv.eth_saddr == mac_addr

      ipv6_addr = adv.ipv6_saddr
      return { eth: mac_addr, ipv4: ipv4_addr, ipv6: ipv6_addr }
    end
    nil
  end

  def neighbor_discovery(neighs)
    print_status('Discovering IPv6 addresses for IPv4 nodes...')
    print_status('')

    smac = @smac
    open_pcap({ 'SNAPLEN' => 68, 'FILTER' => 'icmp6' })

    begin
      neighs.each do |neigh|
        _, dmac = neigh

        shost = ipv6_linklocaladdr(smac)
        neigh = ipv6_linklocaladdr(dmac)

        probe = buildsolicitation(smac, shost, neigh)

        capture.inject(probe)
        Kernel.select(nil, nil, nil, 0.1)

        while (adv = getadvertisement)
          next unless adv.is_ipv6?

          addr = map_neighbor(neighs, adv)
          next if !addr

          print_status(format('  %<ipv4>16s maps to %<ipv6>s', ipv4: addr[:ipv4], ipv6: addr[:ipv6]))
          report_note(
            host: addr[:ipv4],
            type: 'host.ipv4.ipv6.mapping',
            data: {
              ipv4_address: addr[:ipv4],
              ipv6_address: addr[:ipv6],
              matches: 'true'
            }
          )	# with this we have the results in our database

        end
      end

      etime = ::Time.now.to_f + (neighs.length * 0.5)

      while (::Time.now.to_f < etime)
        while (adv = getadvertisement)
          next if !adv

          addr = map_neighbor(neighs, adv)
          next if !addr

          print_status(format('  %<ipv4>16s maps to %<ipv6>s', ipv4: addr[:ipv4], ipv6: addr[:ipv6]))
        end
        ::IO.select(nil, nil, nil, 0.50)
      end
    ensure
      close_pcap
    end
  end

  def buildprobe(shost, smac, dhost)
    p = PacketFu::ARPPacket.new
    p.eth_saddr = smac
    p.eth_daddr = 'ff:ff:ff:ff:ff:ff'
    p.arp_opcode = 1
    p.arp_saddr_mac = p.eth_saddr
    p.arp_daddr_mac = p.eth_daddr
    p.arp_saddr_ip = shost
    p.arp_daddr_ip = dhost
    p.to_s
  end

  def getreply
    pkt = capture.next
    Kernel.select(nil, nil, nil, 0.1)
    return if !pkt

    p = PacketFu::Packet.parse(pkt)
    return unless p.is_arp?
    return unless p.arp_opcode == 2

    p
  end

  def buildsolicitation(smac, shost, neigh)
    dmac = ipv6_soll_mcast_mac(neigh)
    dhost = ipv6_soll_mcast_addr6(neigh)

    p = PacketFu::IPv6Packet.new
    p.eth_saddr = smac
    p.eth_daddr = dmac
    p.ipv6_saddr = shost
    p.ipv6_daddr = dhost
    p.ipv6_next = 0x3a
    p.ipv6_hop = 255
    p.payload = ipv6_neighbor_solicitation(
      IPAddr.new(neigh).to_i,
      p.eth_src
    )
    p.ipv6_len = p.payload.size
    ipv6_checksum!(p)
    p.to_s
  end

  def getadvertisement
    pkt = capture.next
    Kernel.select(nil, nil, nil, 0.1)
    return if !pkt

    p = PacketFu::Packet.parse(pkt)
    return unless p.is_ipv6?
    return unless p.ipv6_next == 0x3a
    return unless p.icmpv6_type == 136 && p.icmpv6_code == 0

    p
  end
end
