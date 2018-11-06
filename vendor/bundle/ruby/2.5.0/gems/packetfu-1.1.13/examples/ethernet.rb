# -*- coding: binary -*-

# Usage:
# ruby examples/ethernet.rb

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)
require 'packetfu'

eth_pkt = PacketFu::EthPacket.new
eth_pkt.eth_saddr="01:02:03:04:05:06"
eth_pkt.eth_daddr="0a:0b:0c:0d:0e:0f"
eth_pkt.payload="I'm a lonely little eth packet with no real protocol information to speak of."
eth_pkt.recalc
puts eth_pkt.inspect
puts eth_pkt.to_f('/tmp/ethernet.pcap').inspect
