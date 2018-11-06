# -*- coding: binary -*-
# This is a somewhat contrived and verbose demonstration of how to implement ARP manually.
#
# It's contrived because this is really how PacketFu::Utils got born; something similiar
# (and a wee bit cleaner) is already available as Packet::Utils::arp, since knowing the
# MAC address of a target IP turns out to be pretty useful day-to-day.

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)
require 'packetfu'

def usage
  if ARGV[0].nil?
    raise ArgumentError, "You need an IP address to start with."
  elsif !Process.euid.zero?
    raise SecurityError, "You need to be root to run this."
  end
end

usage unless target_ip = ARGV[0]		# Need a target IP.
usage unless Process.euid.zero?			# Need to be root.
IPAddr.new(target_ip)								# Check to see it's really an IP address, and not a herring or something.

$packetfu_default = PacketFu::Config.new(PacketFu::Utils.whoami?).config

def arp(target_ip)

  arp_pkt = PacketFu::ARPPacket.new(:flavor => "Windows")
  arp_pkt.eth_saddr = arp_pkt.arp_saddr_mac = $packetfu_default[:eth_saddr]
  arp_pkt.eth_daddr = "ff:ff:ff:ff:ff:ff"
  arp_pkt.arp_daddr_mac = "00:00:00:00:00:00"

  arp_pkt.arp_saddr_ip = $packetfu_default[:ip_saddr]
  arp_pkt.arp_daddr_ip = target_ip

  # Stick the Capture object in its own thread.

  cap_thread = Thread.new do
    cap = PacketFu::Capture.new(:start => true,
                                :filter => "arp src #{target_ip} and ether dst #{arp_pkt.eth_saddr}")
    arp_pkt.to_w # Shorthand for sending single packets to the default interface.
    target_mac = nil
    while target_mac.nil?
      if cap.save > 0
        arp_response = PacketFu::Packet.parse(cap.array[0])
        target_mac = arp_response.arp_saddr_mac if arp_response.arp_saddr_ip = target_ip
      end
      sleep 0.1 # Check for a response ten times per second.
    end
    puts "#{target_ip} is-at #{target_mac}"
    # That's all we need.
    exit 0
  end

  # Timeout for cap_thread
  sleep 3; puts "Oh noes! Couldn't get an arp out of #{target_ip}. Maybe it's not here."
  exit 1
end

arp(target_ip)
