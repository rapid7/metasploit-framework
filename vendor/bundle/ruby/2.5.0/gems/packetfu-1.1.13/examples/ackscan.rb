#!/usr/bin/env ruby
# -*- coding: binary -*-

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)
require 'packetfu'

# Portscanning!
# Run this on one machine
#cap = Capture.new(:iface=>'wlan0') # or whatever your interface is
#cap.show_live(:filter => 'src net 209.85.165')
# Run this on another:
#cap = Capture.new(:iface=>'wlan0') # or whatever your interface is
#cap = Capture.new(:iface=>'wlan0') # or whatever your interface is
# Run this on the third
def do_scan
  puts "Generating packets..."
  pkt_array = gen_packets.sort_by {rand}
  puts "Dumping them on the wire..."
  inj = PacketFu::Inject.new(:iface => ARGV[0])
  inj.array_to_wire(:array=>pkt_array)
  puts "Done!"
end

def gen_packets
  config = PacketFu::Utils.whoami?(:iface=>ARGV[0])
  pkt = PacketFu::TCPPacket.new(:config=>config, :flavor=>"Windows")
  pkt.payload ="all I wanna do is ACK ACK ACK and a RST and take your money"
  pkt.ip_daddr="209.85.165.0"	# One of Google's networks
  pkt.tcp_flags.ack=1
  pkt.tcp_dst=81
  pkt_array = []
  256.times do |i|
   pkt.ip_dst.o4=i
   pkt.tcp_src = rand(5000 - 1025) + 1025
 	 pkt.recalc
 	 pkt_array << pkt.to_s
 	end
 	pkt_array
end

do_scan
