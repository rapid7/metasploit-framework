#!/usr/bin/env ruby
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#Example Output 
#>> nohup sudo simple_cap.rb &
#>> ping www.google.com
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#{"recv"=>0, "drop"=>0, "idrop"=>0}
#{"recv"=>0, "drop"=>0, "idrop"=>0}
#{"recv"=>0, "drop"=>0, "idrop"=>0}
#{"recv"=>2, "drop"=>0, "idrop"=>0}
#captured packet
#{"recv"=>4, "drop"=>0, "idrop"=>0}
#captured packet
#{"recv"=>6, "drop"=>0, "idrop"=>0}
#captured packet 
#....^c
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

require 'rubygems'
require 'pcaprub'
require 'pp'

# Show me all SYN packets:
bpffilter = "tcp[13] & 2 != 0"

filename = './telnet-raw.pcap'
capture = PCAPRUB::Pcap.open_offline(filename)
puts "PCAP.h Version #{capture.pcap_major_version}.#{capture.pcap_minor_version}"

capture.setfilter(bpffilter)
pp capture
