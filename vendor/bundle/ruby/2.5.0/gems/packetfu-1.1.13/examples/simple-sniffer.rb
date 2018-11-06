#!/usr/bin/env ruby
# -*- coding: binary -*-

# Usage:
# rvmsudo ruby examples/simple-sniffer.rb

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)
require 'packetfu'

puts "Simple sniffer for PacketFu #{PacketFu.version}"
include PacketFu
iface = ARGV[0] || PacketFu::Utils.default_int

def sniff(iface)
  cap = Capture.new(:iface => iface, :start => true)
  cap.stream.each do |p|
    pkt = Packet.parse p
    if pkt.is_ip?
      next if pkt.ip_saddr == Utils.ifconfig(iface)[:ip_saddr]
      packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.size, pkt.proto.last]
      puts "%-15s -> %-15s %-4d %s" % packet_info
    end
  end
end

sniff(iface)

=begin
Results look like this:
145.58.33.95    -> 192.168.11.70   1514 TCP
212.233.158.76  -> 192.168.11.70   110  UDP
88.174.164.147  -> 192.168.11.70   110  UDP
145.58.33.95    -> 192.168.11.70   1514 TCP
145.58.33.95    -> 192.168.11.70   1514 TCP
145.58.33.95    -> 192.168.11.70   1514 TCP
145.58.33.95    -> 192.168.11.70   1514 TCP
8.8.8.8         -> 192.168.11.70   143  UDP
41.237.73.186   -> 192.168.11.70   60   TCP
145.58.33.95    -> 192.168.11.70   1514 TCP
145.58.33.95    -> 192.168.11.70   1514 TCP
8.8.8.8         -> 192.168.11.70   143  UDP
8.8.8.8         -> 192.168.11.70   128  UDP
8.8.8.8         -> 192.168.11.70   187  UDP
24.45.247.232   -> 192.168.11.70   70   TCP
=end
