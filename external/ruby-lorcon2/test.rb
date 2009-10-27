#!/usr/bin/env ruby

$:.unshift(File.dirname(__FILE__))
require "Lorcon2"
require "pp"

=begin
$stdout.puts "Checking LORCON version"

pp Lorcon.version

$stdout.puts "\nFetching LORCON driver list" 

pp Lorcon.drivers

$stdout.puts "\nResolving driver by name 'mac80211'"

pp Lorcon.find_driver("mac80211")

$stdout.puts "\nAuto-detecting driver for interface wlan0"

pp Lorcon.auto_driver("mon0")
=end

#tx = Lorcon::Device.new('kismet0', 'tuntap')
tx = Lorcon::Device.new('wlan2')
$stdout.puts "\nCreated LORCON context"

if tx.openinjmon()
	$stdout.puts "\nOpened as INJMON: " + tx.capiface
else
	$stdout.puts "\nFAILED to open " + tx.capiface + " as INJMON: " + tx.error
end

@pkts = 0

Thread.new do 
	while(true)
		select(nil, nil, nil, 5)
		puts "count: #{@pkts}"
	end
end

# tx.filter = "port 80"
tx.each_packet { |pkt| 
	if(pkt.dot3)
		p pkt.dot3
	end
	@pkts += 1
}
