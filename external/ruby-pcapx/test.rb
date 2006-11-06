#!/usr/bin/env ruby
$:.unshift(File.dirname(__FILE__))

require 'pcaplet'
include Pcap



class Time
  # tcpdump style format
  def to_s
    sprintf "%0.2d:%0.2d:%0.2d.%0.6d", hour, min, sec, tv_usec
  end
end

pcaplet = Pcaplet.new('-i ath0 ')
pcaplet.each_packet { |pkt|
  print "#{pkt.time} #{pkt}"
  if pkt.tcp?
    print " (#{pkt.tcp_data_len})"
    print " ack #{pkt.tcp_ack}" if pkt.tcp_ack?
    print " win #{pkt.tcp_win}"
  end
  if pkt.ip?
    print " (DF)" if pkt.ip_df?
  end
  print "\n"
}
pcaplet.close
