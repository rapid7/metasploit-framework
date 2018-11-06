# Uniqpcap.rb takes a pcap file, strips out duplicate packets, and
# writes them to a file.
#
# The duplicate pcap problem is common when I'm capturing
# traffic to/from a VMWare image, for some reason.
#
# Currently, the timestamp information is lost due to PcapRub's
# file read. For me, this isn't a big deal. Future versions
# will deal with timestamps correctly.

# Usage:
# ruby examples/uniqcap.rb test/sample.pcap

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)
require 'packetfu'

pcap_file = ARGV[0].chomp

in_array = PacketFu::Read.f2a(:file => pcap_file)

puts "Original Packets: #{in_array.size}"
puts "Uniq'd Packets: #{in_array.uniq.size}"

puts PacketFu::Write.a2f(:file => pcap_file + ".uniq", :arr => in_array.uniq).inspect
