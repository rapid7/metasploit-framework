#!/usr/bin/env ruby
require 'mkmf'

if have_library("orcon", "tx80211_txpacket")
	create_makefile("Lorcon")
else
	puts "Error: the lorcon library was not found, please see the README"
end
