#!/usr/bin/env ruby

$:.unshift(File.dirname(__FILE__))

require "Lorcon2"
require 'thread'
require "pp"

intf = ARGV.shift || "wlan0"

$stdout.puts "Checking LORCON version"

pp Lorcon.version

$stdout.puts "\nFetching LORCON driver list" 

pp Lorcon.drivers

$stdout.puts "\nResolving driver by name 'mac80211'"

pp Lorcon.find_driver("mac80211")

$stdout.puts "\nAuto-detecting driver for interface wlan0"

pp Lorcon.auto_driver(intf)


tx = Lorcon::Device.new(intf)
$stdout.puts "\nCreated LORCON context"

if tx.openinjmon()
	$stdout.puts "\nOpened as INJMON: " + tx.capiface
else
	$stdout.puts "\nFAILED to open " + tx.capiface + " as INJMON: " + tx.error
end

def safe_loop(wifi)
	@q = Queue.new
	reader = Thread.new do 
		wifi.each_packet {|pkt| @q << pkt }
	end

	eater = Thread.new do
		while(pkt = @q.pop)
			yield(pkt)
		end
	end
	
	begin
		eater.join
	rescue ::Interrupt => e
		reader.kill if reader.alive?
		puts "ALL DONE!"
	end
end
		
safe_loop(tx) do |pkt|
	pp pkt
end
