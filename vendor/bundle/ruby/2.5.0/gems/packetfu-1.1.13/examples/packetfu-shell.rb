# -*- coding: binary -*-

# Usage:
# rvmsudo ruby examples/packetfu-shell.rb

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)

require 'packetfu'
require 'irb'

module PacketFu
  def whoami?(args={})
    Utils.whoami?(args)
  end
  def arp(arg)
    Utils.arp(arg)
  end
end

include PacketFu

# Draws a picture. Includes a nunchuck, so you know that it's serious.
# I /think/ this is how you're supposed to spell it in a kana charset.
# http://jisho.org/words?jap=+%E3%83%91%E3%82%B1%E3%83%83%E3%83%88%E3%83%95&eng=&dict=edict
#
def packetfu_ascii_art
  puts <<EOM
 _______  _______  _______  _        _______ _________ _______
(  ____ )(  ___  )(  ____ \\| \\    /\\(  ____ \\\\__   __/(  ____ \\|\\     /|
| (    )|| (   ) || (    \\/|  \\  / /| (    \\/   ) (   | (    \\/| )   ( |
| (____)|| (___) || |      |  (_/ / | (__       | |   | (__    | |   | |
|  _____)|  ___  || |      |   _ (  |  __)      | |   |  __)   | |   | |
| (      | (   ) || |      |  ( \\ \\ | (         | |   | (      | |   | |
| )      | )   ( || (____/\\|  /  \\ \\| (____/\\   | |   | )      | (___) |
|/       |/     \\|(_______/|_/    \\/(_______/   )_(   |/       (_______)
 ____________________________              ____________________________
(                            )            (                            )
| 01000001 00101101 01001000 )( )( )( )( )( 00101101 01000001 00100001 |
|                            )( )( )( )( )(                            |
(____________________________)            (____________________________)
                               PacketFu
             a mid-level packet manipulation library for ruby

EOM
  end

@pcaprub_loaded = PacketFu.pcaprub_loaded?
# Displays a helpful banner.
def banner
  packetfu_ascii_art
  puts ">>> PacketFu Shell #{PacketFu.version}."
  if Process.euid.zero? && @pcaprub_loaded
    puts ">>> Use $packetfu_default.config for salient networking details."
    print "IP:  %-15s Mac: %s" % [$packetfu_default.ip_saddr, $packetfu_default.eth_saddr]
    puts "   Gateway: %s" % $packetfu_default.eth_daddr
    print "Net: %-15s" % [Pcap.lookupnet($packetfu_default.iface)][0]
    print "  " * 13
    puts "Iface:   %s" % [($packetfu_default.iface)]
    puts ">>> Packet capturing/injecting enabled."
  else
    print ">>> Packet capturing/injecting disabled. "
    puts Process.euid.zero? ? "(no PcapRub)" : "(not root)"
  end
  puts "<>" * 36
end

# Silly wlan0 workaround
begin
  $packetfu_default = PacketFu::Config.new(Utils.whoami?) if(@pcaprub_loaded && Process.euid.zero?)
rescue RuntimeError
  $packetfu_default = PacketFu::Config.new(Utils.whoami?(:iface => 'wlan0')) if(@pcaprub_loaded && Process.euid.zero?)
end

banner

IRB.start
