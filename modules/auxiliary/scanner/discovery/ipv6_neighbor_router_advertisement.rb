##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Capture
  include Msf::Exploit::Remote::Ipv6
  include Msf::Auxiliary::Report
  def initialize
    super(
    'Name'        => 'IPv6 Local Neighbor Discovery Using Router Advertisement',
    'Description' => %q{
        Send a spoofed router advertisement with high priority to force hosts to
        start the IPv6 address auto-config. Monitor for IPv6 host advertisements,
        and try to guess the link-local address by concatenating the prefix, and
        the host portion of the IPv6 address.  Use NDP host solicitation to
        determine if the IP address is valid'
    },
    'Author'      => ['wuntee', 'd0lph1n98'],
    'License'     => MSF_LICENSE,
    'References'    =>
    [
      ['URL','http://wuntee.blogspot.com/2010/11/ipv6-link-local-host-discovery-concept.html']
    ]
    )

    register_options(
    [
      OptInt.new('TIMEOUT_NEIGHBOR', [true, "Time (seconds) to listen for a solicitation response.", 1])
    ])

    deregister_options('SNAPLEN', 'FILTER', 'RHOST', 'PCAPFILE')
  end

  def generate_prefix()
    max = 16 ** 4
    prefix = "2001:"
    (0..2).each do
        prefix << "%x:" % Random.rand(0..max)
    end
    return prefix << ':'
  end

  def listen_for_neighbor_solicitation(opts = {})
    hosts = []
    timeout = opts['TIMEOUT'] || datastore['TIMEOUT']
    prefix = @prefix

    max_epoch = ::Time.now.to_i + timeout
    autoconf_prefix = IPAddr.new(prefix).to_string().slice(0..19)

    while(::Time.now.to_i < max_epoch)
      pkt = capture.next()
      next if not pkt
      p = PacketFu::Packet.parse(pkt)
      next unless p.is_ipv6?
      next unless p.payload
      next if p.payload.empty?
      next unless p.payload[0,1] == "\x87" # Neighbor solicitation
      host_addr = PacketFu::AddrIpv6.new.read(p.payload[8,16]).to_x # Fixed position yay
      # Make sure host portion is the same as what we requested
      host_addr_prefix = IPAddr.new(host_addr).to_string().slice(0..19)
      next unless host_addr_prefix == autoconf_prefix
      next unless hosts.index(host_addr).nil?
      hosts.push(host_addr)
      print_status("   |*| #{host_addr}")
    end

    return(hosts)
  end

  def find_link_local(opts = {})
    shost = opts['SHOST'] || datastore['SHOST'] || ipv6_link_address
    hosts = opts['HOSTS'] || []
    smac  = @smac
    timeout = opts['TIMEOUT_NEIGHBOR'] || datastore['TIMEOUT_NEIGHBOR']
    network_prefix = Rex::Socket.addr_aton(shost)[0,8]

    hosts.each() do |g|
      host_postfix = Rex::Socket.addr_aton(g)[8,8]
      local_ipv6   = Rex::Socket.addr_ntoa(network_prefix + host_postfix)
      mac = solicit_ipv6_mac(local_ipv6, {"TIMEOUT" => timeout})
      if mac
        # report_host(:mac => mac, :host => local_ipv6)
        print_status("   |*| #{local_ipv6} -> #{mac}")
      end
    end
  end

  def create_router_advertisment(opts={})
    dhost = "FF02::1"
    smac = @smac
    shost = opts['SHOST'] || datastore['SHOST'] || ipv6_link_address
    lifetime = opts['LIFETIME'] || datastore['TIMEOUT']
    prefix = @prefix
    plen = 64
    dmac = "33:33:00:00:00:01"

    p = PacketFu::IPv6Packet.new
    p.eth_saddr = smac
    p.eth_daddr = dmac
    p.ipv6_hop = 255
    p.ipv6_next = 0x3a
    p.ipv6_saddr = shost
    p.ipv6_daddr = dhost

    payload = router_advertisement_payload
    payload << opt60_payload(lifetime, prefix)
    payload << slla_payload(smac)
    p.payload = payload
    p.ipv6_len = payload.size
    ipv6_checksum!(p)
    return p
  end

  def opt60_payload(lifetime, prefix)
    type = 3
    len = 4
    prefix_len = 64
    flag = 0xc0
    valid_lifetime = lifetime || 5
    preferred_lifetime = lifetime || 5
    reserved = 0
    prefix = IPAddr.new(prefix).to_i.to_s(16).scan(/../).map {|x| x.to_i(16)}.pack("C*")
    [type, len, prefix_len, flag, valid_lifetime,
      preferred_lifetime, reserved, prefix].pack("CCCCNNNa16")
  end

  def slla_payload(smac)
    type = 1
    len = 1
    addr = PacketFu::EthHeader.mac2str(smac)
    [type,len,addr].pack("CCa6")
  end

  def router_advertisement_payload
    type = 0x86
    code = 0
    checksum = 0
    hop_limit = 0
    flags = 0x08
    lifetime = 0
    reachable = 0
    retrans = 0
    [type, code, checksum, hop_limit, flags,
      lifetime, reachable, retrans].pack("CCnCCnNN")
  end

  def run
    # Start capture
    open_pcap({'FILTER' => "icmp6"})

    @prefix = generate_prefix()
    @netifaces = true
    if not netifaces_implemented?
      print_error("WARNING : Pcaprub is not uptodate, some functionality will not be available")
      @netifaces = false
    end

    @interface = datastore['INTERFACE'] || Pcap.lookupdev
    @shost = datastore['SHOST']
    @shost ||= get_ipv4_addr(@interface) if @netifaces
    raise 'SHOST should be defined' unless @shost

    @smac  = datastore['SMAC']
    @smac ||= get_mac(@interface) if @netifaces
    @smac ||= ipv6_mac
    raise 'SMAC should be defined' unless @smac

    # Send router advertisement
    print_status("Sending router advertisement...")
    pkt = create_router_advertisment()
    capture.inject(pkt.to_s)

    # Listen for host advertisements
    print_status("Listening for neighbor solicitation...")
    hosts = listen_for_neighbor_solicitation()

    if(hosts.size() == 0)
      print_status("No hosts were seen sending a neighbor solicitation")
    else
      # Attempt to get link local addresses
      print_status("Attempting to solicit link-local addresses...")
      find_link_local({"HOSTS" => hosts})
    end

    # Close capture
    close_pcap()
  end
end
