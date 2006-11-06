#!/usr/local/bin/ruby
require 'pcaplet'
httpdump = Pcaplet.new('-s 1500')

HTTP_REQUEST  = Pcap::Filter.new('tcp and dst port 80', httpdump.capture)
HTTP_RESPONSE = Pcap::Filter.new('tcp and src port 80', httpdump.capture)

httpdump.add_filter(HTTP_REQUEST | HTTP_RESPONSE)
httpdump.each_packet {|pkt|
  data = pkt.tcp_data
  case pkt
  when HTTP_REQUEST
    if data and data =~ /^GET\s+(\S+)/
      path = $1
      host = pkt.dst.to_s
      host << ":#{pkt.dst_port}" if pkt.dport != 80
      s = "#{pkt.src}:#{pkt.sport} > GET http://#{host}#{path}"
    end
  when HTTP_RESPONSE
    if data and data =~ /^(HTTP\/.*)$/
      status = $1
      s = "#{pkt.dst}:#{pkt.dport} < #{status}"
    end
  end
  puts s if s
}
