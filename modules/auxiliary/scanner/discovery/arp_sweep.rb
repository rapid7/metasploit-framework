##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Capture
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  OUI_LIST = Rex::Oui

  def initialize
    super(
      'Name' => 'ARP Sweep Local Network Discovery',
      'Description' => %q{
        Enumerate alive hosts in local network using ARP requests.
      },
      'Author' => 'belch',
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS],
        'Reliability' => []
      }
    )

    register_options([
      OptString.new('SHOST', [false, 'Source IP Address']),
      OptString.new('SMAC', [false, 'Source MAC Address']),
      # one re-register TIMEOUT here with a lower value, cause 5 seconds will be enough in most of the case
      OptInt.new('TIMEOUT', [true, 'The number of seconds to wait for new data', 5]),
    ])

    deregister_options('SNAPLEN', 'FILTER', 'PCAPFILE', 'SECRET', 'GATEWAY_PROBE_HOST', 'GATEWAY_PROBE_PORT')
  end

  def run_batch_size
    datastore['BATCHSIZE'] || 256
  end

  def run_batch(hosts)
    open_pcap({ 'SNAPLEN' => 68, 'FILTER' => 'arp[6:2] == 0x0002' })

    @netifaces = true
    if !netifaces_implemented?
      print_error('WARNING : NetworkInterface is not up-to-date, some functionality will not be available')
      @netifaces = false
    end

    @interface = datastore['INTERFACE'] || Pcap.lookupdev
    shost = datastore['SHOST']
    shost ||= get_ipv4_addr(@interface) if @netifaces
    raise 'SHOST should be defined' unless shost

    smac = datastore['SMAC']
    smac ||= get_mac(@interface) if @netifaces
    raise 'SMAC should be defined' unless smac

    begin
      hosts.each do |dhost|
        next unless dhost != shost

        probe = buildprobe(shost, smac, dhost)
        inject(probe)

        while (reply = getreply)
          next unless reply.is_arp?

          company = OUI_LIST.lookup_oui_company_name(reply.arp_saddr_mac)
          print_good("#{reply.arp_saddr_ip} appears to be up (#{company}).")
          report_host(host: reply.arp_saddr_ip, mac: reply.arp_saddr_mac)
          report_note(host: reply.arp_saddr_ip, type: 'mac_oui', data: { company: company })
        end
      end

      etime = Time.now.to_f + datastore['TIMEOUT']
      while (Time.now.to_f < etime)
        while (reply = getreply)
          next unless reply.is_arp?

          company = OUI_LIST.lookup_oui_company_name(reply.arp_saddr_mac)
          print_good("#{reply.arp_saddr_ip} appears to be up (#{company}).")
          report_host(host: reply.arp_saddr_ip, mac: reply.arp_saddr_mac)
          report_note(host: reply.arp_saddr_ip, type: 'mac_oui', data: { company: company })
        end
        Kernel.select(nil, nil, nil, 0.50)
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
    p.recalc
    p
  end

  def getreply
    pkt_bytes = capture.next
    Kernel.select(nil, nil, nil, 0.1)
    return unless pkt_bytes

    pkt = PacketFu::Packet.parse(pkt_bytes)
    return unless pkt.is_arp?
    return unless pkt.arp_opcode == 2

    pkt
  end
end
