#!/usr/bin/env ruby
# -*- coding: binary -*-

# new-simple-stats.rb demonstrates the performance difference
# between the old and busted way to parse pcap files and the
# new hotness of stream parsing. Spoiler alert: Against a pcap
# file of 1GB, the old way would eat all your memory and take
# forever. This still takes kinda forever, but at 5000 packets
# every 11 seconds (my own benchmark) for this script, at least
# it doesn't hog up all your memory.

# Usage:
# ruby examples/new-simple-stats.rb test/sample.pcap

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)
require 'packetfu'

def print_results(stats)
  stats.each_pair { |k,v| puts "%-12s: %10d" % [k,v] }
end

# Takes a file name, parses the packets, and records the packet
# type based on its PacketFu class.
def count_packet_types(file)
  stats = {}
  count = 0
  elapsed = 0
  start_time = Time.now
  PacketFu::PcapFile.read_packets(file) do |pkt|
    kind = pkt.proto.last.to_sym
    stats[kind] ? stats[kind] += 1 : stats[kind] = 1
    count += 1
    elapsed = (Time.now - start_time).to_i
    if count % 5_000 == 0
      puts "After #{count} packets (#{elapsed} seconds elapsed):"
      print_results(stats)
    end
  end
  puts "Final results for #{count} packets (#{elapsed} seconds elapsed):"
  print_results(stats)
end

if File.readable?(infile = (ARGV[0] || 'in.pcap'))
  title = "Packets by packet type in '#{infile}'"
  puts "-" * title.size
  puts title
  puts "-" * title.size
  count_packet_types(infile)
else
  raise RuntimeError, "Need an infile, like so: #{$0} in.pcap"
end
