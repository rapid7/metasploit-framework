#!/usr/bin/env ruby
# Copyright (C) 2007 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 

module Scruby

# General help
def help(command = nil)

  if command.nil?
    print <<EOF
This is Scruby, a portable, customizable packet creation and sending/sniffing tool written in Ruby. It was tested on NetBSD, GNU/Linux and MacOS X, and should theoretically work on some other platforms such as FreeBSD, OpenBSD and proprietary Unixes.

See http://sylv1.tuxfamily.org/projects/scruby.html for more information.

With Scruby, you can:
- create custom packet: p=IP(:src=>"1.2.3.4", :dst=>"www.google.com")/TCP()/"GET / HTTP 1.0\\r\\n\\r\\n"
- send custom packets at layer 2: sendp(Ether(:src=>"00:11:22:33:44:55")/p)
- sniff on an interface: sniff(:iface=>"eth1")
- read packets from a PCAP file: sniff(:offline=>"mycapture.pcap")
- dissect a string to a recreate the packet: s=p.to_net;puts "string=\#{s.inspect}\\nresult=\#{IP(s)}"

Available dissectors (type "ls 'MyDissector'" to have detailed information):
#{Scruby.dissectors.keys.sort.join(", ")}

Available functions (type "lsc 'myfunction'" to have detailed information):
#{(Scruby.methods - Object.methods).sort.join(", ")}
EOF
  else
    # Executing the specific help function
    eval(command.to_s + '_help')	
  end
end

# Help on sniff
def sniff_help

    print <<EOF
This function captures packets on an interface or reads a PCAP file. The default capture interface is stored in @conf.iface, currently "#{@conf.iface}".

Without any argument, sniff captures on the default interface:
example> sniff
listening on eth0
1158608918.45960 <Ether dst=00:11:22:33:44:55 src=55:44:33:22:11:00 |><IP len=84 proto=1 chksum=0x7c0f src=1.2.3.4 dst=4.3.2.1 |><ICMP chksum=17905 id=16922 seq=1 |>

1158608918.124147 <Ether dst=55:44:33:22:11:00 src=00:11:22:33:44:55 |><IP len=84 ttl=244 proto=1 chksum=0xc80e src=4.3.2.1 dst=1.2.3.4 |><ICMP type=0 chksum=19953 id=16922 seq=1 |>

The following arguments are available (with the default values between brackets):
- iface: the interface to listen on (@conf.iface, currently "#{@conf.iface}")
- prn: a function that will be called for each packet received (:sniff_simple)
- filter: a PCAP filter (undef)
- count: the number of packets to capture. An argument less than or equal to 0 will read "loop forever" (-1)
- promisc: capture in promiscuous mode or not (@conf.promisc, currently "#{@conf.promisc}")
- timeout: capture timeout in milliseconds (#{TIMEOUT}, seems not to work?)
- offline: PCAP file to read packets from
- store: not implemented yet

The prn argument is the most interesting one, it allows you to customize the behaviour of the sniff function:

example> def my_prn(pcap, packet) puts "GOT ONE: raw=|\#{packet.inspect}|" end
example> sniff(:iface=>"eth1", :prn=>:my_prn, :filter=>"icmp", :count=>2)
listening on eth0
GOT ONE: raw=|"\000\a\313\fg\246\000Pp4\210\264\b\000E\000\000T\000\000@\000@\001\030KR\357\313I\324\e0\n\b\000\336\t4\031\000\001\001\202\252ED\021\v\000\b\t\n\v\f\r\016\017\020\021\022\023\024\025\026\027\030\031\032\e\034\035\036\037 !\"\#$%&'()*+,-./01234567"|

Note that by default, captured packets are not stored in memory for performance reason. To stop sniffing, press ^C.

To read from a PCAP file:
example> sniff(:offline=>"mycapture.pcap")
EOF
end

# Help on send
def send_help
    print <<EOF
NOT IMPLEMENTED YET
This function sends a packet at layer 3 on the default interface (@conf.iface, currently "#{@conf.iface}"). If not specified, the Ethernet destination is @conf.gateway_hwaddr (currently "#{@conf.gateway_hwaddr}". 

If Libdnet is available, source IP address is automatically filled according to this interface.

example> p=IP(:src=>"1.2.3.4", :dst=>"www.google.com")/TCP()/"GET / HTTP 1.0\\r\\n\\r\\n"
example> send(p)
Sent.
EOF
end

# Help on sendp
def sendp_help
    print <<EOF
This function sends a packet at layer 2 on the default interface (@conf.iface, currently "#{@conf.iface}"). If not specified, the Ethernet destination will be @conf.gateway_hwaddr (currently "#{@conf.gateway_hwaddr}").

If Libdnet is available, source Ethernet address and source IP address are automatically filled according to this interface.

example> p=Ether(:src=>"00:11:22:33:44:55")/IP(:src=>"1.2.3.4", :dst=>"www.google.com")/TCP()/"GET / HTTP 1.0\\r\\n\\r\\n"
example> sendp(p)
Sent on eth0.
EOF
end

# Help on ls
def Scruby.ls_help
  print <<EOF
This function lists the available dissectors. Type "ls 'MyDissector'" to have detailed information on one of them.
EOF
end

# Help on lsc
def Scruby.lsc_help
  print <<EOF
Yeah, you've found an Easter Egg!!
EOF
end

end