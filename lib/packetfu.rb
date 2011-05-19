
# :title: PacketFu Documentation
# :include: ../README
# :include: ../INSTALL
# :include: ../LICENSE

$: << File.expand_path(File.dirname(__FILE__))
require "packetfu/structfu"
require "ipaddr"
require 'rubygems' if RUBY_VERSION =~ /^1\.[0-8]/

module PacketFu

	# Sets the expected byte order for a pcap file. See PacketFu::Read.set_byte_order
	@byte_order = :little

	# Checks if pcaprub is loaded correctly.
	@@pcaprub_loaded = false
	
	# PacketFu works best with Pcaprub version 0.8-dev (at least)
	# The current (Aug 01, 2010) pcaprub gem is 0.9, so should be fine.
  def self.pcaprub_platform_require
		begin
			require 'pcaprub'
		rescue LoadError
			return false
		end
      @@pcaprub_loaded = true 
  end

	pcaprub_platform_require
	if @@pcaprub_loaded
		if Pcap.version !~ /[0-9]\.[7-9][0-9]?(-dev)?/ # Regex for 0.7-dev and beyond.
			@@pcaprub_loaded = false # Don't bother with broken versions
			raise LoadError, "PcapRub not at a minimum version of 0.8-dev"
		end
		require "packetfu/capture" 
		require "packetfu/inject"
	end

end

require "packetfu/pcap"
require "packetfu/packet"
require "packetfu/invalid"
require "packetfu/eth"
require "packetfu/ip" 
require "packetfu/arp"
require "packetfu/icmp"
require "packetfu/udp"
require "packetfu/hsrp" # Depends on UDP
require "packetfu/tcp"
require "packetfu/ipv6" # This is pretty minimal.
require "packetfu/utils"
require "packetfu/config"

module PacketFu

	# Version 1.0.0 was released July 31, 2010
	# Version 1.0.1 is unreleased.
	VERSION = "1.0.1" 

	# Returns the current version of PacketFu. Incremented every once 
	# in a while, when I remember
	def self.version
		PacketFu::VERSION
	end

	# Returns the version in a binary format for easy comparisons.
	def self.binarize_version(str)
		if(str.respond_to?(:split) && str =~ /^[0-9]+(\.([0-9]+)(\.[0-9]+)?)?$/)
			bin_major,bin_minor,bin_teeny = str.split(/\x2e/).map {|x| x.to_i}
			bin_version = (bin_major.to_i << 16) + (bin_minor.to_i << 8) + bin_teeny.to_i
		else
			raise ArgumentError, "Compare version malformed. Should be \x22x.y.z\x22"
		end
	end

	# Returns true if the version is equal to or greater than the compare version.
	# If the current version of PacketFu is "0.3.1" for example:
	#
	#   PacketFu.at_least? "0"     # => true 
	#   PacketFu.at_least? "0.2.9" # => true 
	#   PacketFu.at_least? "0.3"   # => true 
	#   PacketFu.at_least? "1"     # => true after 1.0's release
	#   PacketFu.at_least? "1.12"  # => false
	#   PacketFu.at_least? "2"     # => false 
	def self.at_least?(str)
		this_version = binarize_version(self.version)
		ask_version = binarize_version(str)
		this_version >= ask_version
	end

	# Returns true if the current version is older than the compare version.
	def self.older_than?(str)
		this_version = binarize_version(self.version)
		ask_version = binarize_version(str)
		this_version < ask_version
	end

	# Returns true if the current version is newer than the compare version.
	def self.newer_than?(str)
		return false if str == self.version
		!self.older_than?(str)
	end

end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
