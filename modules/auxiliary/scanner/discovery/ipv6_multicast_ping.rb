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
    'Name'        => 'IPv6 Link Local/Node Local Ping Discovery',
    'Description' => %q{
        Send a ICMPv6 ping request to all default multicast addresses, and wait to see who responds.
    },
    'Author'      => 'wuntee',
    'License'     => MSF_LICENSE,
    'References'    =>
      [
        ['URL','http://wuntee.blogspot.com/2010/12/ipv6-ping-host-discovery-metasploit.html']
      ]
    )

    deregister_options('SNAPLEN', 'FILTER', 'PCAPFILE')
  end

  def listen_for_ping_response(opts = {})
    hosts = {}
    timeout = opts['TIMEOUT'] || datastore['TIMEOUT']
    prefix = opts['PREFIX'] || datastore['PREFIX']

    max_epoch = ::Time.now.to_i + timeout

    while(::Time.now.to_i < max_epoch)
      pkt_bytes = capture.next()
      Kernel.select(nil,nil,nil,0.1)
      next if not pkt_bytes
      p = PacketFu::Packet.parse(pkt_bytes)
      # Don't bother checking if it's an echo reply, since Neighbor Solicitations
      # and any other response is just as good.
      next unless p.is_ipv6?
      host_addr = p.ipv6_saddr
      host_mac = p.eth_saddr
      next if host_mac == @smac
      unless hosts[host_addr] == host_mac
        hosts[host_addr] = host_mac
        print_status("   |*| #{host_addr} => #{host_mac}")
      end
    end
    return hosts
  end

  def smac
    smac  = datastore['SMAC']
    smac ||= get_mac(@interface) if @netifaces
    smac ||= ipv6_mac
    smac
  end

  def run
    # Start capture
    open_pcap({'FILTER' => "icmp6"})

    @netifaces = true
    if not netifaces_implemented?
      print_error("WARNING : Pcaprub is not uptodate, some functionality will not be available")
      @netifaces = false
    end

    @interface = datastore['INTERFACE'] || Pcap.lookupdev

    # Send ping
    print_status("Sending multicast pings...")
    dmac = "33:33:00:00:00:01"
    @smac = smac
    # Figure out our source address by the link-local interface
    shost = ipv6_link_address

    # m-1-k-3: added some more multicast addresses from wikipedia: https://en.wikipedia.org/wiki/Multicast_address#IPv6
    ping6("FF01::1", {"DMAC" => dmac, "SHOST" => shost, "SMAC" =>  @smac, "WAIT" => false})    #node-local all nodes
    ping6("FF01::2", {"DMAC" => dmac, "SHOST" => shost, "SMAC" =>  @smac, "WAIT" => false})    #node-local all routers
    ping6("FF02::1", {"DMAC" => dmac, "SHOST" => shost, "SMAC" =>  @smac, "WAIT" => false})    #All nodes on the local network segment
    ping6("FF02::2", {"DMAC" => dmac, "SHOST" => shost, "SMAC" =>  @smac, "WAIT" => false})    #All routers on the local network segment
    ping6("FF02::5", {"DMAC" => dmac, "SHOST" => shost, "SMAC" =>  @smac, "WAIT" => false})    #OSPFv3 AllSPF routers
    ping6("FF02::6", {"DMAC" => dmac, "SHOST" => shost, "SMAC" =>  @smac, "WAIT" => false})    #OSPFv3 AllDR routers
    ping6("FF02::9", {"DMAC" => dmac, "SHOST" => shost, "SMAC" =>  @smac, "WAIT" => false})    #RIP routers
    ping6("FF02::a", {"DMAC" => dmac, "SHOST" => shost, "SMAC" =>  @smac, "WAIT" => false})    #EIGRP routers
    ping6("FF02::d", {"DMAC" => dmac, "SHOST" => shost, "SMAC" =>  @smac, "WAIT" => false})    #PIM routers
    ping6("FF02::16", {"DMAC" => dmac, "SHOST" => shost, "SMAC" =>  @smac, "WAIT" => false})   #MLDv2 reports (defined in RFC 3810)
    ping6("ff02::1:2", {"DMAC" => dmac, "SHOST" => shost, "SMAC" =>  @smac, "WAIT" => false})  #All DHCP servers and relay agents on the local network site (defined in RFC 3315)
    ping6("ff05::1:3", {"DMAC" => dmac, "SHOST" => shost, "SMAC" =>  @smac, "WAIT" => false})  #All DHCP servers on the local network site (defined in RFC 3315)

    # Listen for host advertisments
    print_status("Listening for responses...")
    listen_for_ping_response()

    # Close capture
    close_pcap()
  end
end
