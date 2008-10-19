#!/usr/bin/env ruby
# Copyright (C) 2007 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 

$LOAD_PATH << '../'

def test(is, should)
  eval("module Scruby;require 'scruby';$r = #{is}.to_s == '#{should}';end;")
  if not $r
    puts "\n## test #{$test_nb} FALSE##"
    puts is.to_s    
  else
    print "."
  end
  $test_nb += 1
end

module Scruby
require 'scruby'

$test_nb = 1

puts "BEGIN"

# Constructor arguments
test("IP(nil)", "<IP |>")
test("IP('')", "<IP |>")
test("IP(:foobar)", "<IP |>")
test("IP(Hash.new)", "<IP |>")
test("IP(Array.new)", "<IP |>")

# All dissectors
test("Ether()", "<Ether |>")
test("ARP()", "<ARP |>")
test("IP()", "<IP |>")
test("ICMP()", "<ICMP |>")
test("Raw()", "<Raw |>")
test("TCP()", "<TCP |>")
test("UDP()", "<UDP |>")
test("ClassicBSDLoopback()", "<ClassicBSDLoopback |>")
test("OpenBSDLoopback()", "<OpenBSDLoopback |>")
test("RIFF()", "<RIFF |>")
test("ANI()", "<ANI |>")
test("Dot11()", "<Dot11 |>")
test("Dot11QoS()", "<Dot11QoS |>")
test("Dot11Beacon()", "<Dot11Beacon |>")
test("Dot11Elt()", "<Dot11Elt |>")
test("Dot11ATIM()", "<Dot11ATIM |>")
test("Dot11Disas()", "<Dot11Disas |>")
test("Dot11AssoReq()", "<Dot11AssoReq |>")
test("Dot11AssoResp()", "<Dot11AssoResp |>")
test("Dot11ReassoReq()", "<Dot11ReassoReq |>")
test("Dot11ReassoResp()", "<Dot11ReassoResp |>")
test("Dot11ProbeReq()", "<Dot11ProbeReq |>")
test("Dot11ProbeResp()", "<Dot11ProbeResp |>")
test("Dot11Auth()", "<Dot11Auth |>")
test("Dot11Deauth()", "<Dot11Deauth |>")
test("Dot11WEP()", "<Dot11WEP |>")
test("LLC()", "<LLC |>")

# All dissectors with arguments
test("Ether(:dst=>'11:11:11:11:11:11', :src=>'22:22:22:22:22:22', :type=>666)", "<Ether dst=11:11:11:11:11:11 src=22:22:22:22:22:22 type=0x29a |>")
test("ARP(:hwtype=>'FrameRelay', :ptype=>3, :hwlen=>1, :plen=>'IPv6', :op=>2, :hwsrc=>'11:22:33:44:55:66', :psrc=>'192.168.0.1', :hwdst=>'66:55:44:33:22:11', :pdst=>'192.168.0.2')", "<ARP hwtype=0xf ptype=0x3 hwlen=1 plen=16 op=2 hwsrc=11:22:33:44:55:66 psrc=\"192.168.0.1\" hwdst=66:55:44:33:22:11 pdst=\"192.168.0.2\" |>")
test("IP(:version=>3, :ihl=>4, :tos=>101, :len=>102, :id=>103, :flags=>'DF', :frag=>104, :ttl=>105, :proto=>106, :chksum=>107, :src=>'10.0.0.1', :dst=>'10.0.0.2')", "<IP version=3 ihl=4 tos=0x65 len=102 id=0x67 flags=2 frag=104 ttl=105 proto=106 chksum=0x6b src=\"10.0.0.1\" dst=\"10.0.0.2\" |>")
test("TCP(:sport=>100, :dport=>101, :seq=>102, :ack=>103, :dataofs=>109, :reserved=>104, :flags=>'SYN ACK', :window=>106, :chksum=>107, :urgptr=>108)", "<TCP sport=100 dport=101 seq=102 ack=103 dataofs=109 reserved=104 flags=18 window=106 chksum=0x6b urgptr=108 |>")
test("UDP(:sport=>100, :dport=>101, :len=>102, :chksum=>103)", "<UDP sport=100 dport=101 len=102 chksum=0x67 |>")
test("ICMP(:type=>100, :code=>101, :chksum=>102, :id=>103, :seq=>104)", "<ICMP type=100 code=101 chksum=0x66 id=0x67 seq=0x68 |>")
test("Raw(:load=>'foobar')", "<Raw load=\"foobar\" |>")
test("ClassicBSDLoopback(:header=>100)", "<ClassicBSDLoopback header=100 |>")
test("OpenBSDLoopback(:header=>100)", "<OpenBSDLoopback header=100 |>")
test("RIFF(:id=>'FOOB', :size=>66, :headerid=>'BARZ')", "<RIFF id=\"FOOB\" size=66 headerid=\"BARZ\" |>")
test("ANI(:id=>'foob', :size=>12, :headersize=>21, :frames=>3, :steps=>1, :width=>2, :height=>3, :bitcount=>4, :planes=>5, :displayrate=>6, :icon=>1, :sequence=>1, :reserved=>1)", "<ANI id=\"foob\" size=12 headersize=21 frames=3 steps=1 width=2 height=3 bitcount=4 planes=5 displayrate=6 icon=1 sequence=1 reserved=1 |>")
test("Dot11(:subtype=>1, :type=>1, :proto=>1, :FCfield=>1, :ID=>1, :addr1=>'11:11:11:11:11:11', :addr2=>'22:22:22:22:22:22', :addr3=>'33:33:33:33:33:33')", "<Dot11 subtype=1 type=1 proto=1 FCfield=1 ID=1 addr1=11:11:11:11:11:11 addr2=22:22:22:22:22:22 addr3=33:33:33:33:33:33 |>")
test("Dot11Elt(:ID=>1, :len=>2, :info=>'ab')", "<Dot11Elt ID=1 len=2 info=\"ab\" |>")
test("LLC(:dsap=>1, :ssap=>1, :ctrl=>1)", "<LLC dsap=0x1 ssap=0x1 ctrl=1 |>")

# Fields for Ether
test("Ether().dst", "00:00:00:00:00:00")
test("Ether().src", "00:00:00:00:00:00")
test("Ether().type", "2048")

# Fields for ARP
test("ARP().hwtype", "1")
test("ARP().ptype", "2048")
test("ARP().hwlen", "6")
test("ARP().plen", "4")
test("ARP().op", "1")
test("ARP().hwsrc", "00:00:00:00:00:00")
test("ARP().psrc", "127.0.0.1")
test("ARP().hwdst", "00:00:00:00:00:00")
test("ARP().pdst", "127.0.0.1")

# Fields for IP
test("IP().version", "4")
test("IP().ihl", "5")
test("IP().tos", "0")
test("IP().len", "20")
test("IP().id", "0")
test("IP().flags", "0")
test("IP().frag", "0")
test("IP().ttl", "64")
test("IP().proto", "6")
test("IP().chksum", "0")
test("IP().src", "127.0.0.1")
test("IP().dst", "127.0.0.1")

# Fields for TCP
test("TCP().sport", "1024")
test("TCP().dport", "80")
test("TCP().seq", "0")
test("TCP().ack", "0")
test("TCP().dataofs", "5")
test("TCP().reserved", "0")
test("TCP().flags", "2")
test("TCP().window", "8192")
test("TCP().chksum", "0")
test("TCP().urgptr", "0")

# Fields for UDP
test("UDP().sport", "53")
test("UDP().dport", "53")
test("UDP().len", "8")
test("UDP().chksum", "0")

# Fields for ICMP
test("ICMP().type", "8")
test("ICMP().code", "0")
test("ICMP().chksum", "0")
test("ICMP().id", "0")
test("ICMP().seq", "0")

# Fields for Raw
test("Raw().load", "")

# Fields for ClassicBSDLoopback
test("ClassicBSDLoopback().header", "2")

# Fields for OpenBSDLoopback
test("OpenBSDLoopback().header", "2")

# Fields for RIFF
test("RIFF().id", "RIFF")
test("RIFF().size", "0")
test("RIFF().headerid", "ACON")

# Fields for ANI
test("ANI().id", "anih")
test("ANI().size", "36")
test("ANI().headersize", "36")
test("ANI().frames", "2")
test("ANI().steps", "0")
test("ANI().width", "0")
test("ANI().height", "0")
test("ANI().bitcount", "0")
test("ANI().planes", "0")
test("ANI().displayrate", "0")
test("ANI().icon", "0")
test("ANI().sequence", "0")
test("ANI().reserved", "0")

# Fields for Dot11
test("Dot11().subtype", "0")
test("Dot11().type", "2")
test("Dot11().proto", "0")
test("Dot11().FCfield", "0")
test("Dot11().ID", "0")
test("Dot11().addr1", "00:00:00:00:00:00")
test("Dot11().addr2", "00:00:00:00:00:00")
test("Dot11().addr3", "00:00:00:00:00:00")
test("Dot11().SC", "0")
test("Dot11().addr4", "00:00:00:00:00:00")

# Fields for Dot11Elt
test("Dot11Elt().ID", "0")
test("Dot11Elt().len", "0")
test("Dot11Elt().info", "")

# Fields for LLC
test("LLC().dsap", "0")
test("LLC().ssap", "0")
test("LLC().ctrl", "0")

# Ether packet
test("Ether(:src=>'ba:98:76:54:32:10', :type=>123).to_net.inspect", "\000\000\000\000\000\000\272\230vT2\020\000{".inspect)
test("Ether(:dst=>'01:23:45:67:89:ab', :src=>'ba:98:76:54:32:10', :type=>123).to_net.inspect", "\001#Eg\211\253\272\230vT2\020\000{".inspect)

# ARP packet
test("(Ether(:type=>'ARP')/ARP(:hwtype=>'Ethernet', :ptype=>0x800, :hwlen=>6, :plen=>'IPv4', :op=>2, :hwsrc=>'11:22:33:44:55:66', :psrc=>'192.168.0.1', :hwdst=>'66:55:44:33:22:11', :pdst=>'192.168.0.2')).to_net.inspect", "\000\000\000\000\000\000\000\000\000\000\000\000\b\006\000\001\b\000\006\004\000\002\021\"3DUf\300\250\000\001fUD3\"\021\300\250\000\002".inspect)

# IP packet
test("(IP(:version=>4, :ihl=>5, :tos=>13, :id=>103, :flags=>2, :frag=>104, :ttl=>105, :proto=>106, :src=>'1.2.3.4', :dst=>'4.3.2.1')/Raw(:load=>\"foobar\")).to_net.inspect", "E\r\000\032\000g@hij\006\225\001\002\003\004\004\003\002\001foobar".inspect)

# TCP packet
test("(IP()/TCP(:sport=>100, :dport=>101, :seq=>102, :ack=>103, :dataofs=>5, :reserved=>3, :flags=>3, :window=>106, :urgptr=>108)).to_net.inspect", "E\000\000(\000\000\000\000@\006|\316\177\000\000\001\177\000\000\001\000d\000e\000\000\000f\000\000\000gS\003\000j\254s\000l".inspect)

# UDP packet
test("(IP(:proto=>17)/UDP(:sport=>100, :dport=>101)/Raw(:load=>\"foobar\")).to_net.inspect", "E\000\000\"\000\000\000\000@\021|\311\177\000\000\001\177\000\000\001\000d\000e\000\016\311\302foobar".inspect)

# ICMP packet
test("(IP(:proto=>1)/ICMP(:type=>0, :code=>101, :id=>103, :seq=>104)).to_net.inspect", "E\000\000\034\000\000\000\000@\001|\337\177\000\000\001\177\000\000\001\000e\376\313\000g\000h".inspect)

# RIFF packet
test("RIFF(:id=>'FOOB', :size=>67, :headerid=>'BARZ').to_net.inspect", "FOOBC\000\000\000BARZ".inspect)

# ANI packet
test("ANI(:id=>'foob', :size=>12, :headersize=>21, :frames=>3, :steps=>1, :width=>2, :height=>3, :bitcount=>4, :planes=>5, :displayrate=>6, :icon=>1, :sequence=>1, :reserved=>1).to_net.inspect", "foob\f\000\000\000\025\000\000\000\003\000\000\000\001\000\000\000\002\000\000\000\003\000\000\000\004\000\000\000\005\000\000\000\006\000\000\000\300\000\000\001".inspect)

# Dot11 packet
test("Dot11(:subtype=>1, :type=>1, :proto=>1, :FCfield=>1, :ID=>1, :addr1=>'11:11:11:11:11:11', :addr2=>'22:22:22:22:22:22', :addr3=>'33:33:33:33:33:33').to_net.inspect", "\025\001\000\001\021\021\021\021\021\021".inspect)

# Dot11Elt packet
test("Dot11Elt(:ID=>1, :len=>2, :info=>'ab').to_net.inspect", "\001\002ab".inspect)

# LLC
test("LLC(:dsap=>1, :ssap=>1, :ctrl=>1).to_net.inspect", "\001\001\001".inspect)

# Dissecting Ether
test("Ether(\"\001#Eg\211\253\272\230vT2\020\000{\")", "<Ether dst=01:23:45:67:89:ab src=ba:98:76:54:32:10 type=0x7b |>")

# Dissecting ARP
test('ARP("\000\001\b\000\006\004\000\002\021\"3DUf\300\250\000\001fUD3\"\021\300\250\000\002")', "<ARP op=2 hwsrc=11:22:33:44:55:66 psrc=\"192.168.0.1\" hwdst=66:55:44:33:22:11 pdst=\"192.168.0.2\" |>")

# Dissecting IP
test("IP(\"E\r\000\032\000g@hij\006\225\001\002\003\004\004\003\002\001foobar\")", "<IP tos=0xd len=26 id=0x67 flags=2 frag=104 ttl=105 proto=106 chksum=0x695 src=\"1.2.3.4\" dst=\"4.3.2.1\" |><Raw load=\"foobar\" |>")

# Dissecting TCP
test("TCP(\"\000d\000e\000\000\000f\000\000\000gS\003\000j\254s\000l\")", "<TCP sport=100 dport=101 seq=102 ack=103 reserved=3 flags=3 window=106 chksum=0xac73 urgptr=108 |>")

# Dissecting UDP
test("UDP(\"\000d\000e\000\016\311\302foobar\")", "<UDP sport=100 dport=101 len=14 chksum=0xc9c2 |><Raw load=\"foobar\" |>")

# Dissecting ICMP
test("ICMP(\"\000e\376\313\000g\000h\")", "<ICMP type=0 code=101 chksum=0xfecb id=0x67 seq=0x68 |>")

# Dissecting a string
test("Raw('foobar')", "<Raw load=\"foobar\" |>")

# Dissecting RIFF
test('RIFF("FOOBC\000\000\000BARZ")', "<RIFF id=\"FOOB\" size=67 headerid=\"BARZ\" |>")

# Dissecting ANI
test('ANI("foob\f\000\000\000\025\000\000\000\003\000\000\000\001\000\000\000\002\000\000\000\003\000\000\000\004\000\000\000\005\000\000\000\006\000\000\000\300\000\000\001")', "<ANI id=\"foob\" size=12 headersize=21 frames=3 steps=1 width=2 height=3 bitcount=4 planes=5 displayrate=6 icon=1 sequence=1 reserved=1 |>")

# Dissecting Dot11
test('Dot11("\025\001\000\001\021\021\021\021\021\021")', "<Dot11 subtype=1 type=1 proto=1 FCfield=1 ID=1 addr1=11:11:11:11:11:11 |>")

# Dissecting Dot11Elt
test('Dot11Elt("\001\002ab")', "<Dot11Elt ID=1 len=2 info=\"ab\" |>")

# Dissecting a real Dot11 string
test('Dot11("\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x19}\x01Y\xc4\x00\x19}\x01Y\xc4\xf0\x1e\x8bA\x9f\t)\x0c\x00\x00d\x00\x11\x04\x00\x0cLivebox-6708\x01\x08\x82\x84\x8b\x96$0Hl\x03\x01\x01\x05\x04\x00\x03\x00\x00*\x01\x00/\x01\x002\x04\x0c\x12\x18`\xdd\x16\x00P\x02\x01\x01\x00\x00P\x02\x02\x01\x00\x00P\x02\x02\x01\x00\x00P\x02\x02\xdd\x18\x00P\x02\x02")', "<Dot11 subtype=8 type=0 addr1=ff:ff:ff:ff:ff:ff addr2=00:19:7d:01:59:c4 addr3=00:19:7d:01:59:c4 SC=7920 |><Dot11Beacon timestamp=13370394624395 cap=4356 |><Dot11Elt len=12 info=\"Livebox-6708\" |><Dot11Elt ID=1 len=8 info=\"\\202\\204\\213\\226$0Hl\" |><Dot11Elt ID=3 len=1 info=\"\\001\" |><Dot11Elt ID=5 len=4 info=\"\\000\\003\\000\\000\" |><Dot11Elt ID=42 len=1 info=\"\\000\" |><Dot11Elt ID=47 len=1 info=\"\\000\" |><Dot11Elt ID=50 len=4 info=\"\\f\\022\\030`\" |><Dot11Elt ID=221 len=22 info=\"\\000P\\002\\001\\001\\000\\000P\\002\\002\\001\\000\\000P\\002\\002\\001\\000\\000P\\002\\002\" |><Dot11Elt ID=221 len=24 info=\"\\000P\\002\\002\" |>")

# Dissecting LLC
test('LLC("\001\001\001")', "<LLC dsap=0x1 ssap=0x1 ctrl=1 |>")

# Operations on layers
$p=Ether()/"E\000\000.\000\000\000\000@\006|\310\177\000\000\001\177\000\000\001\004\000\000P\000\000\000\000\000\000\000\000P\002 \000VF\000\000foobar"
$p.decode_payload_as(IP)

test("$p", "<Ether |><IP len=46 chksum=0x7cc8 |><TCP chksum=0x5646 |><Raw load=\"foobar\" |>")
test("$p.has_layer(IP)", "true")
test("$p.has_layer(UDP)", "false")
test("$p.last_layer", "<Raw load=\"foobar\" |>")
test("$p.get_layer(TCP)", "<TCP chksum=0x5646 |><Raw load=\"foobar\" |>")

# Dissecting a string byte after byte
test("IP('A')", "<IP ihl=1 |>")
test("IP('A'*2)", "<IP ihl=1 tos=0x41 |>")
test("IP('A'*3)", "<IP ihl=1 tos=0x41 |>")
test("IP('A'*4)", "<IP ihl=1 tos=0x41 len=16705 |>")
test("IP('A'*5)", "<IP ihl=1 tos=0x41 len=16705 |>")
test("IP('A'*6)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 |>")
test("IP('A'*7)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 |>")
test("IP('A'*8)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 |>")
test("IP('A'*9)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 |>")
test("IP('A'*10)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 |>")
test("IP('A'*11)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 |>")
test("IP('A'*12)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 chksum=0x4141 |>")
test("IP('A'*13)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 chksum=0x4141 |>")
test("IP('A'*14)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 chksum=0x4141 |>")
test("IP('A'*15)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 chksum=0x4141 |>")
test("IP('A'*16)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 chksum=0x4141 src=\"65.65.65.65\" |>")
test("IP('A'*17)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 chksum=0x4141 src=\"65.65.65.65\" |>")
test("IP('A'*18)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 chksum=0x4141 src=\"65.65.65.65\" |>")
test("IP('A'*19)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 chksum=0x4141 src=\"65.65.65.65\" |>")
test("IP('A'*20)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 chksum=0x4141 src=\"65.65.65.65\" dst=\"65.65.65.65\" |>")
test("IP('A'*21)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 chksum=0x4141 src=\"65.65.65.65\" dst=\"65.65.65.65\" |><Raw load=\"A\" |>")



#List of fields
#echo 'Fields:';grep 'class ' field.rb | cut -f 2 -d " " | cut -f 1 -d "<"
puts "\nFields: #{Scruby.fields.keys.sort.join(", ")}"

#List of dissectors
#echo 'Dissectors:';grep 'class ' dissector.rb | cut -f 2 -d " " | cut -f 1 -d "<"
puts "\nDissectors: #{Scruby.dissectors.keys.sort.join(", ")}"

#List of functions
#echo 'Functions:';grep 'def Scruby' func.rb | cut -f 2 -d "." | cut -f 1 -d "("
puts "\nFunctions: #{(Scruby.methods - Object.methods).sort.join(", ")}"

puts "\nEND"
puts "Now, read the end of this file for the last things to do."

# Modify the CHANGELOG to add new fields, dissectors and functions
# Check layer_bounds
# Test every function
# Check help
# Reread, recheck and modify the HTML documentation

end