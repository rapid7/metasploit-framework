# PacketFu

[![Build Status](https://secure.travis-ci.org/packetfu/packetfu.png)](http://travis-ci.org/packetfu/packetfu)
[![Code Climate](https://codeclimate.com/github/packetfu/packetfu.png)](https://codeclimate.com/github/packetfu/packetfu)
[![Coverage Status](https://coveralls.io/repos/github/packetfu/packetfu/badge.svg?branch=master)](https://coveralls.io/github/packetfu/packetfu?branch=master)

A library for reading and writing packets to an interface or to a
libpcap-formatted file.

It is maintained [here](https://github.com/packetfu/packetfu).

## Setup

To install the gem, type

```bash
gem install packetfu
```

To install from source, type

```bash
gem install bundler
git clone https://github.com/packetfu/packetfu.git
cd packetfu
bundle install
```

## Quick Start

The best way to test your installation is by using [packetfu-shell](https://github.com/packetfu/packetfu/blob/master/examples/packetfu-shell.rb), like so

```bash
$ rvmsudo ruby examples/packetfu-shell.rb
 _______  _______  _______  _        _______ _________ _______
(  ____ )(  ___  )(  ____ \| \    /\(  ____ \\__   __/(  ____ \|\     /|
| (    )|| (   ) || (    \/|  \  / /| (    \/   ) (   | (    \/| )   ( |
| (____)|| (___) || |      |  (_/ / | (__       | |   | (__    | |   | |
|  _____)|  ___  || |      |   _ (  |  __)      | |   |  __)   | |   | |
| (      | (   ) || |      |  ( \ \ | (         | |   | (      | |   | |
| )      | )   ( || (____/\|  /  \ \| (____/\   | |   | )      | (___) |
|/       |/     \|(_______/|_/    \/(_______/   )_(   |/       (_______)
 ____________________________              ____________________________
(                            )            (                            )
| 01000001 00101101 01001000 )( )( )( )( )( 00101101 01000001 00100001 |
|                            )( )( )( )( )(                            |
(____________________________)            (____________________________)
                               PacketFu
             a mid-level packet manipulation library for ruby

>>> PacketFu Shell 1.1.12.
>>> Use $packetfu_default.config for salient networking details.
IP:  192.168.0.100   Mac: ac:bc:32:85:47:3f   Gateway: ec:08:6b:62:bc:d2
Net: 192.168.0.0                              Iface:   en0
>>> Packet capturing/injecting enabled.
<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
2.3.0 :001 >
```

Once you're a this point, you're in an IRB (aka: [REPL](https://en.wikipedia.org/wiki/Read%E2%80%93eval%E2%80%93print_loop)) interface when you can start creating and injection packets with PacketFu.

Here's an example of creating a TCPPacket and sending it out on the wire:

```
2.3.0 :002 > packet = TCPPacket.new(:config => Utils.whoami?)
 => --EthHeader-------------------------------------------
  eth_dst      ec:08:6b:62:bc:d2 PacketFu::EthMac
  eth_src      ac:bc:32:85:47:3f PacketFu::EthMac
  eth_proto    0x0800            StructFu::Int16
--IPHeader--------------------------------------------
  ip_v         4                 Integer
  ip_hl        5                 Integer
  ip_tos       0                 StructFu::Int8
  ip_len       20                StructFu::Int16
  ip_id        0x77e4            StructFu::Int16
  ip_frag      0                 StructFu::Int16
  ip_ttl       32                StructFu::Int8
  ip_proto     6                 StructFu::Int8
  ip_sum       0xffff            StructFu::Int16
  ip_src       192.168.0.100     PacketFu::Octets
  ip_dst       0.0.0.0           PacketFu::Octets
--TCPHeader-------------------------------------------
  tcp_src      42653             StructFu::Int16
  tcp_dst      0                 StructFu::Int16
  tcp_seq      0x8d65fbbf        StructFu::Int32
  tcp_ack      0x00000000        StructFu::Int32
  tcp_hlen     5                 PacketFu::TcpHlen
  tcp_reserved 0                 PacketFu::TcpReserved
  tcp_ecn      0                 PacketFu::TcpEcn
  tcp_flags    ......            PacketFu::TcpFlags
  tcp_win      16384             StructFu::Int16
  tcp_sum      0x7f29            StructFu::Int16
  tcp_urg      0                 StructFu::Int16
  tcp_opts                       PacketFu::TcpOptions

2.3.0 :003 > packet.ip_dst = "8.8.8.8"
 => "8.8.8.8"
2.3.0 :004 > packet.tcp_dst = 53
 => 53
2.3.0 :005 > packet.to_w
 => [1, 1, 54]
```

## Documentation

PacketFu is yard-compatible (as well as sdoc/rdoc, if you prefer). You
can generate local documentation easily with either `yard doc .` or
`sdoc`, and view doc/index.html with your favored browser. Once that's
done, navigate at the top, and read up on how to create a Packet or
Capture from an interface with show_live or whatever.

## Supported Rubies

This project is integrated with travis-ci and is regularly tested to work with the following rubies:

- 2.1.6
- 2.2.3
- 2.3.0

To checkout the current build status for these rubies, click [here](https://travis-ci.org/packetfu/packetfu).

## Author

PacketFu is maintained primarily by Tod Beardsley todb@packetfu.com and
Jonathan Claudius claudijd@yahoo.com, with help from Open Source Land.

See [LICENSE](https://github.com/packetfu/packetfu/blob/master/LICENSE.txt) for licensing details.
