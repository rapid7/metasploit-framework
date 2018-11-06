#!/usr/bin/env ruby
# -*- coding: binary -*-

# Simple-stats.rb takes a pcap file, and gives some simple
# stastics on the protocols found. It's mainly used to
# demonstrate a method to parse pcap files.
#
# XXX: DO NOT USE THIS METHOD TO READ PCAP FILES.
#
# See new-simple-stats.rb for an example of the streaming
# parsing method.

# Usage:
# ruby examples/simple-stats.rb test/sample.pcap

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)
require 'packetfu'

# Takes a file name, parses the packets, and records the packet
# type based on its PacketFu class.
def count_packet_types(file)
  file = File.open(file) {|f| f.read}
  stats = {}
  count = 0
  pcapfile = PacketFu::PcapPackets.new
  pcapfile.read(file)
  pcapfile.each do |p|
    # Now it's a PacketFu packet struct.
    pkt = PacketFu::Packet.parse(p.data)
    kind = pkt.class.to_s.split("::").last
    if stats[kind]
      stats[kind] += 1
    else
      stats[kind] = 0
    end
    count += 1
    break if count >= 1_000
  end
  stats.each_pair { |k,v| puts "%-12s: %4d" % [k,v] }
end

if File.readable?(infile = (ARGV[0] || 'in.pcap'))
  title = "Packets by packet type in '#{infile}'"
  puts title
  puts "-" * title.size
  count_packet_types(infile)
else
  raise RuntimeError, "Need an infile, like so: #{$0} in.pcap"
end
