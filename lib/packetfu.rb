if VERSION < "1.8.5"
	$stderr.puts "[*] WARNING: Ruby not at a minimum version of 1.8.5"
end

require 'bindata'

# This version requirement is a bit of a lie; we need svn version 
# 99 or later, so we can make use of this commit:
# r99 | dmendel | 2008-07-24 23:45:49 -0500 (Thu, 24 Jul 2008) | 1 line
#
# Allow arrays to read until eof
#
# So, for now, PacketFu will distribute with a slightly forked BinData.
# We'll unfork when 0.9.3 is released and all will be right with the world.
if BinData::VERSION < "0.9.2-eofpatch"
	raise LoadError, "BinData not at version 0.9.2-eofpatch"
end

require 'ipaddr'
require 'singleton'

module PacketFu
	@@pcaprub_loaded = false
	begin
		require 'pcaprub'
		if Pcap.version < "0.8-dev"
			@@pcaprub_loaded = false # Don't bother with broken versions
			raise LoadError, "PcapRub not at a minimum version of 0.8-dev"
		end
		require 'packetfu/capture' 
		require 'packetfu/read' 	
		require 'packetfu/inject'
	rescue LoadError
	end
end

# Doesn't require PcapRub
require 'packetfu/pcap'
require 'packetfu/write' 

# Packet crafting/parsing goodness.
require 'packetfu/packet'
require 'packetfu/invalid'
require 'packetfu/eth'
require 'packetfu/ip'
require 'packetfu/arp'
require 'packetfu/icmp'
require 'packetfu/udp'
require 'packetfu/tcp'
require 'packetfu/ipv6'

# Various often-used utilities.
require 'packetfu/utils'

# A place to keep defaults.
require 'packetfu/config'

#:main:PacketFu
#
#:include:../README
#:include:../LICENSE

module PacketFu

	# Returns the version.
	def self.version
		"0.1.0" # September 13, 2008
	end

end
