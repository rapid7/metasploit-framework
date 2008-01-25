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
test("IP(nil)", "<IP |>") #1
test("IP('')", "<IP |>")
test("IP(:foobar)", "<IP |>")
test("IP(Hash.new)", "<IP |>")
test("IP(Array.new)", "<IP |>")

# All dissectors
test("Ether()", "<Ether |>") #6
test("IP()", "<IP |>")
test("TCP()", "<TCP |>")
test("UDP()", "<UDP |>")
test("ICMP()", "<ICMP |>")
test("Raw()", "<Raw |>")
test("ClassicBSDLoopback()", "<ClassicBSDLoopback |>")
test("OpenBSDLoopback()", "<OpenBSDLoopback |>")

# All dissectors with arguments
test("Ether(:dst=>'11:11:11:11:11:11', :src=>'22:22:22:22:22:22', :type=>666)", "<Ether dst=11:11:11:11:11:11 src=22:22:22:22:22:22 type=0x29a |>") #14
test("IP(:version=>3, :ihl=>4, :tos=>101, :len=>102, :id=>103, :flags=>2, :frag=>104, :ttl=>105, :proto=>106, :chksum=>107, :src=>'10.0.0.1', :dst=>'10.0.0.2')", "<IP version=3 ihl=4 tos=0x65 len=102 id=0x67 flags=2 frag=104 ttl=105 proto=106 chksum=0x6b src=\"10.0.0.1\" dst=\"10.0.0.2\" |>")
test("TCP(:sport=>100, :dport=>101, :seq=>102, :ack=>103, :dataofs=>109, :reserved=>104, :flags=>105, :window=>106, :chksum=>107, :urgptr=>108)", "<TCP sport=100 dport=101 seq=102 ack=103 dataofs=109 reserved=104 flags=0x69 window=106 chksum=0x6b urgptr=108 |>")
test("UDP(:sport=>100, :dport=>101, :len=>102, :chksum=>103)", "<UDP sport=100 dport=101 len=102 chksum=0x67 |>")
test("ICMP(:type=>100, :code=>101, :chksum=>102, :id=>103, :seq=>104)", "<ICMP type=100 code=101 chksum=0x66 id=0x67 seq=0x68 |>")
test("Raw(:load=>'foobar')", "<Raw load=\"foobar\" |>")
test("ClassicBSDLoopback(:header=>100)", "<ClassicBSDLoopback header=100 |>")
test("OpenBSDLoopback(:header=>100)", "<OpenBSDLoopback header=100 |>")

# Fields for Ether
test("Ether().dst", "00:00:00:00:00:00") #22
test("Ether().src", "00:00:00:00:00:00")
test("Ether().type", "2048")

# Fields for IP
test("IP().version", "4") #25
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
test("TCP().sport", "1024") #37
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
test("UDP().sport", "53") #47
test("UDP().dport", "53")
test("UDP().len", "8")
test("UDP().chksum", "0")

# Fields for ICMP
test("ICMP().type", "8") #51
test("ICMP().code", "0")
test("ICMP().chksum", "0")
test("ICMP().id", "0")
test("ICMP().seq", "0")

# Fields for Raw
test("Raw().load", "") #56

# Fields for ClassicBSDLoopback
test("ClassicBSDLoopback().header", "2")

# Fields for OpenBSDLoopback
test("OpenBSDLoopback().header", "2")

# Dissecting a string
test("Raw('foobar')", "<Raw load=\"foobar\" |>")

# Ether packet #60
test("Ether(:src=>'ba:98:76:54:32:10', :type=>123).to_net.inspect", "\000\000\000\000\000\000\272\230vT2\020\000{".inspect)
test("Ether(:dst=>'01:23:45:67:89:ab', :src=>'ba:98:76:54:32:10', :type=>123).to_net.inspect", "\001#Eg\211\253\272\230vT2\020\000{".inspect)

# IP packet #62
test("(IP(:version=>4, :ihl=>5, :tos=>13, :id=>103, :flags=>2, :frag=>104, :ttl=>105, :proto=>106, :src=>'1.2.3.4', :dst=>'4.3.2.1')/Raw(:load=>\"foobar\")).to_net.inspect", "E\r\000\032\000g@hij\006\225\001\002\003\004\004\003\002\001foobar".inspect)

# TCP packet
test("(IP()/TCP(:sport=>100, :dport=>101, :seq=>102, :ack=>103, :dataofs=>5, :reserved=>3, :flags=>3, :window=>106, :urgptr=>108)).to_net.inspect", "E\000\000(\000\000\000\000@\006|\316\177\000\000\001\177\000\000\001\000d\000e\000\000\000f\000\000\000gS\003\000j\254s\000l".inspect)

# UDP packet
test("(IP(:proto=>17)/UDP(:sport=>100, :dport=>101)/Raw(:load=>\"foobar\")).to_net.inspect", "E\000\000\"\000\000\000\000@\021|\311\177\000\000\001\177\000\000\001\000d\000e\000\016\311\302foobar".inspect)

# ICMP packet
test("(IP(:proto=>1)/ICMP(:type=>0, :code=>101, :id=>103, :seq=>104)).to_net.inspect", "E\000\000\034\000\000\000\000@\001|\337\177\000\000\001\177\000\000\001\000e\376\313\000g\000h".inspect)

# Dissecting Ether #66
test("Ether(\"\001#Eg\211\253\272\230vT2\020\000{\")", "<Ether dst=01:23:45:67:89:ab src=ba:98:76:54:32:10 type=0x7b |>")

# Dissecting IP
test("IP(\"E\r\000\032\000g@hij\006\225\001\002\003\004\004\003\002\001foobar\")", "<IP tos=0xd len=26 id=0x67 flags=2 frag=104 ttl=105 proto=106 chksum=0x695 src=\"1.2.3.4\" dst=\"4.3.2.1\" |><Raw load=\"foobar\" |>")

# Dissecting TCP
test("TCP(\"\000d\000e\000\000\000f\000\000\000gS\003\000j\254s\000l\")", "<TCP sport=100 dport=101 seq=102 ack=103 reserved=3 flags=0x3 window=106 chksum=0xac73 urgptr=108 |>")

# Dissecting UDP
test("UDP(\"\000d\000e\000\016\311\302foobar\")", "<UDP sport=100 dport=101 len=14 chksum=0xc9c2 |><Raw load=\"foobar\" |>")

# Dissecting ICMP
test("ICMP(\"\000e\376\313\000g\000h\")", "<ICMP type=0 code=101 chksum=0xfecb id=0x67 seq=0x68 |>")

# Operations on layers # 71
$p=Ether()/"E\000\000.\000\000\000\000@\006|\310\177\000\000\001\177\000\000\001\004\000\000P\000\000\000\000\000\000\000\000P\002 \000VF\000\000foobar"
$p.decode_payload_as(IP)

test("$p", "<Ether |><IP len=46 chksum=0x7cc8 |><TCP chksum=0x5646 |><Raw load=\"foobar\" |>")
test("$p.has_layer(IP)", "true")
test("$p.has_layer(UDP)", "false")
test("$p.last_layer", "<Raw load=\"foobar\" |>")
test("$p.get_layer(TCP)", "<TCP chksum=0x5646 |><Raw load=\"foobar\" |>")

# Dissecting a string byte after byte
test("IP('A')", "<IP ihl=1 |>") # 76
test("IP('A'*2)", "<IP ihl=1 tos=0x41 |>")
test("IP('A'*3)", "<IP ihl=1 tos=0x41 |>")
test("IP('A'*4)", "<IP ihl=1 tos=0x41 len=16705 |>")
test("IP('A'*5)", "<IP ihl=1 tos=0x41 len=16705 |>") # 80
test("IP('A'*6)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 |>")
test("IP('A'*7)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 |>")
test("IP('A'*8)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 |>")
test("IP('A'*9)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 |>")
test("IP('A'*10)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 |>")
test("IP('A'*11)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 |>")
test("IP('A'*12)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 chksum=0x4141 |>")
test("IP('A'*13)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 chksum=0x4141 |>")
test("IP('A'*14)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 chksum=0x4141 |>")
test("IP('A'*15)", "<IP ihl=1 tos=0x41 len=16705 id=0x4141 flags=2 frag=321 ttl=65 proto=65 chksum=0x4141 |>") # 90
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
