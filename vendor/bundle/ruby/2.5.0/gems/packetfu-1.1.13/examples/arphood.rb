#!/usr/bin/env ruby
# -*- coding: binary -*-

# A simple local network fingerprinter. Uses the OUI list.
# Usage:
# rvmsudo examples/arphood.rb [iface] [network] <oui.txt>

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)
require 'packetfu'
require 'open-uri'

$oui_prefixes = {}
$arp_results = []
def build_oui_list
  if ARGV[2].nil?
    puts "Fetching the oui.txt from IEEE, it'll be a second. Avoid this with #{$0} [iface] [network] <filename>."
  oui_file = open("http://standards.ieee.org/regauth/oui/oui.txt")
  else
  oui_file =	File.open(ARGV[2], "rb")
  end
  oui_file.each do |oui_line|
    maybe_oui = oui_line.scan(/^[0-9a-f]{2}\-[0-9a-f]{2}\-[0-9a-f]{2}/i)[0]
    unless maybe_oui.nil?
      oui_value = maybe_oui
      oui_vendor = oui_line.split(/\(hex\)\s*/n)[1] || "PRIVATE"
      $oui_prefixes[oui_value] = oui_vendor.chomp
    end
  end
end

build_oui_list

$root_ok = true if Process.euid.zero?

def arp_everyone
  my_net = PacketFu::Config.new(PacketFu::Utils.whoami?(:iface =>(ARGV[0] || 'wlan0')))
  threads = []
  network = ARGV[1] || "192.168.2"
  print "Arping around..."
  253.times do |i|
    threads[i] = Thread.new do
      this_host = network + ".#{i+1}"
      print "."
      colon_mac = PacketFu::Utils.arp(this_host,my_net.config)
      unless colon_mac.nil?
        hyphen_mac = colon_mac.tr(':','-').upcase[0,8]
      else
        hyphen_mac = colon_mac = "NOTHERE"
      end
      $arp_results <<  "%s : %s / %s" % [this_host,colon_mac,$oui_prefixes[hyphen_mac]]
    end
  end
  threads.each {|thr| thr.join}
end

if $root_ok
  arp_everyone
  puts "\n"
  sleep 3
  $arp_results.sort.each {|a| puts a unless a =~ /NOTHERE/}
end
