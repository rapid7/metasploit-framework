#!/usr/bin/env ruby
# -*- coding: binary -*-
# This just allows you to eyeball the dissection stuff to make sure it's all right.

# Usage:
# ruby examples/ethernet.rb

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)
require 'packetfu'
include PacketFu

fname = ARGV[0] || "test/sample.pcap"
sleep_interval = ARGV[1] || 1

puts "Loaded: PacketFu v#{PacketFu.version}"

packets = PacketFu::PcapFile.file_to_array fname
packets.each do |packet|
  puts "_" * 75
  puts packet.inspect
  puts "_" * 75
  pkt = Packet.parse(packet)
  puts pkt.dissect
  sleep sleep_interval
end
