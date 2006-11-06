#!/usr/local/bin/ruby
require 'pcap'

dev = Pcap.lookupdev
cap = Pcap::Capture.open_live(dev)
cap.setfilter("ip")
cap.loop do |pkt|
    print pkt, "\n"
end
cap.close
