#!/usr/bin/env ruby
require 'mkmf'

if (have_library("orcon", "tx80211_txpacket", "tx80211.h") or find_library("orcon", "tx80211_txpacket", "tx80211.h"))
	create_makefile("Lorcon")
else
	puts "Error: the lorcon library was not found, please see the README"
end
