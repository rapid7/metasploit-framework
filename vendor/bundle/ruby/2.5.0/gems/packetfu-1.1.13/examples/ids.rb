#!/usr/bin/env ruby
# -*- coding: binary -*-

# Usage:
# rvmsudo ruby examples/idsv2.rb

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)
require 'packetfu'

iface = ARGV[0] || PacketFu::Utils.default_int

cap = PacketFu::Capture.new(:iface => iface, :start => true, :filter => "ip")

loop do
  cap.stream.each do |pkt|
    packet = PacketFu::Packet.parse(pkt)
    if packet.payload =~ /^\x04\x01{50}/
      p "#{Time.now}: %s slammed %s" % [packet.ip_saddr, packet.ip_daddr]
    end
  end
end
