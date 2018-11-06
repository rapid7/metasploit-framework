#!/usr/bin/env ruby
# -*- coding: binary -*-

# Usage:
# rvmsudo ruby examples/idsv2.rb

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)
require 'packetfu'

iface = ARGV[0] || PacketFu::Utils.default_int

cap = PacketFu::Capture.new(:iface => iface, :start => true, :filter => "ip")

attack_patterns = ["^gotcha", "owned!*$", "^\x04[^\x00]{50}"]

loop do
  cap.stream.each do |pkt|
    packet = PacketFu::Packet.parse(pkt)
    attack_patterns.each do |sig|
      hit = packet.payload.scan(/#{sig}/i) || nil
      puts "#{Time.now}: %s attacked %s [%s]" % [packet.ip_saddr, packet.ip_daddr, sig.inspect] unless hit.size.zero?
    end
  end
end
