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

capture = PCAPRUB::Pcap.open_live('wlan0', 65535, true, 0)
capture.setfilter('icmp')
while 1==1
  puts(capture.stats())
  pkt = capture.next()
  if pkt
     puts "captured packet" 
  end
  sleep(1)
end
