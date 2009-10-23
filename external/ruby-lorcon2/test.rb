#!/usr/bin/env ruby

$:.unshift(File.dirname(__FILE__))
require "Lorcon2"
require "pp"

$stdout.puts "Checking LORCON version"

pp Lorcon.version

$stdout.puts "\nFetching LORCON driver list" 

pp Lorcon.drivers

$stdout.puts "\nResolving driver by name 'mac80211'"

pp Lorcon.find_driver("mac80211")

$stdout.puts "\nAuto-detecting driver for interface wlan0"

pp Lorcon.auto_driver("mon0")

#tx = Lorcon::Device.new('kismet0', 'tuntap')
tx = Lorcon::Device.new('mon0')
$stdout.puts "\nCreated LORCON context"

if tx.openinjmon()
	$stdout.puts "\nOpened as INJMON: " + tx.capiface
else
	$stdout.puts "\nFAILED to open " + tx.capiface + " as INJMON: " + tx.error
end

tx.channel = 11
scan_patterns = ["^GET ([^ ?]+)"]

tx.each_packet { |pkt| 
	d3 = pkt.dot3

	if d3 != nil then 
		p3pfu = PacketFu::Packet.parse(d3)

		scan_patterns.each {|sig| hit = p3pfu.payload.scan(/#{sig}/i) || nil 
		 	printf "#{Time.now}: %s HTTP GET %s [%s] SEQ %u\n" % [p3pfu.ip_saddr, p3pfu.ip_daddr, sig, p3pfu.tcp_seq] unless hit.size.zero? 
		}
	end
}


# tx.fmode      = "INJECT"
# tx.channel    = 11
# tx.txrate     = 2
# tx.modulation = "DSSS"
# 
# sa = Time.now.to_f
# tx.write(packet, 500, 0)
# ea = Time.now.to_f - sa
# 
# sb = Time.now.to_f
# 500.times { tx.write(packet, 1, 0) }
# eb = Time.now.to_f - sb
# 
# $stdout.puts "Sent 500 packets (C) in #{ea.to_s} seconds"
# $stdout.puts "Sent 500 packets (Ruby) in #{eb.to_s} seconds"
