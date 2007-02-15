#!/usr/bin/env ruby
$:.unshift(File.dirname(__FILE__))
$:.unshift(File.join(File.dirname(__FILE__), 'lib'))

require 'pcapletx'
include PcapX

class Time
	# tcpdump style format
	def to_s
		sprintf "%0.2d:%0.2d:%0.2d.%0.6d", hour, min, sec, tv_usec
	end
end

pcaplet = PcapletX.new(ARGV.join(' '))

pcaplet.each_packet do |pkt|
	print "#{pkt.time} #{pkt} #{pkt.datalink} #{pkt.raw_data.index("\xff" * 6)}"
	if pkt.tcp?
		print " (#{pkt.tcp_data_len})"
		print " ack #{pkt.tcp_ack}" if pkt.tcp_ack?
		print " win #{pkt.tcp_win}"
	end
	if pkt.ip?
		print " (DF)" if pkt.ip_df?
	end
	print "\n"
end


pcaplet.close
