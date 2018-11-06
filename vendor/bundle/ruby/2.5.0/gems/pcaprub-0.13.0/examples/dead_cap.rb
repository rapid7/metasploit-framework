#!/usr/bin/env ruby

# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

require 'rubygems'
require 'pcaprub'


capture = PCAPRUB::Pcap.open_dead(Pcap::DLT_EN10MB, 65535)
puts capture.pcap_major_version()
puts capture.pcap_minor_version()

