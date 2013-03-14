# -*- coding: binary -*-

# :title: PacketFu Documentation
# :main: README

cwd = File.expand_path(File.dirname(__FILE__))

$: << cwd

require File.join(cwd,"packetfu","structfu")
require "ipaddr"
require 'rubygems' if RUBY_VERSION =~ /^1\.[0-8]/

module PacketFu

	# Picks up all the protocols defined in the protos subdirectory
	def self.require_protos(cwd)
		protos_dir = File.join(cwd, "packetfu", "protos")
		Dir.new(protos_dir).each do |fname|
			next unless fname[/\.rb$/]
			begin 
				require File.join(protos_dir,fname)
			rescue
				warn "Warning: Could not load `#{fname}'. Skipping."
			end
		end
	end

	# Deal with Ruby's encoding by ignoring it.
	def self.force_binary(str)
		str.force_encoding "binary" if str.respond_to? :force_encoding
	end

	# Sets the expected byte order for a pcap file. See PacketFu::Read.set_byte_order
	@byte_order = :little

	# Checks if pcaprub is loaded correctly.
	@pcaprub_loaded = false

	# PacketFu works best with Pcaprub version 0.8-dev (at least)
	# The current (Aug 01, 2010) pcaprub gem is 0.9, so should be fine.
	def self.pcaprub_platform_require
		begin
			require 'pcaprub'
		rescue LoadError
			return false
		end
		@pcaprub_loaded = true 
	end

	pcaprub_platform_require

	if @pcaprub_loaded
		pcaprub_regex = /[0-9]\.([8-9]|[1-7][0-9])(-dev)?/ # Regex for 0.8 and beyond.
		if Pcap.version !~ pcaprub_regex 
			@pcaprub_loaded = false # Don't bother with broken versions
			raise LoadError, "PcapRub not at a minimum version of 0.8-dev"
		end
		require "packetfu/capture" 
		require "packetfu/inject"
	end

	# Returns the status of pcaprub
	def self.pcaprub_loaded?
		@pcaprub_loaded
	end

	# Returns an array of classes defined in PacketFu
	def self.classes
		constants.map { |const| const_get(const) if const_get(const).kind_of? Class}.compact
	end

	# Adds the class to PacketFu's list of packet classes -- used in packet parsing.
	def self.add_packet_class(klass)
		raise "Need a class" unless klass.kind_of? Class
		if klass.name !~ /[A-Za-z0-9]Packet/
			raise "Packet classes should be named 'ProtoPacket'"
		end
		@packet_classes ||= []
		@packet_classes << klass
		@packet_classes.sort! {|x,y| x.name <=> y.name}
	end

	# Presumably, there may be a time where you'd like to remove a packet class.
	def self.remove_packet_class(klass)
		raise "Need a class" unless klass.kind_of? Class
		@packet_classes ||= []
		@packet_classes.delete klass
		@packet_classes 
	end

	# Returns an array of packet classes
	def self.packet_classes
		@packet_classes || []
	end

	# Returns an array of packet types by packet prefix.
	def self.packet_prefixes
		return [] unless @packet_classes
		@packet_classes.map {|p| p.to_s.split("::").last.to_s.downcase.gsub(/packet$/,"")}
	end

	# The current inspect style. One of :hex, :dissect, or :default
	# Note that :default means Ruby's default, which is usually
	# far too long to be useful.
	def self.inspect_style
		@inspect_style ||= :dissect
	end

	# Setter for PacketFu's @inspect_style
	def self.inspect_style=(arg)
		@inspect_style = case arg
			when :hex, :pretty
				:hex
			when :dissect, :verbose
				:dissect
			when :default, :ugly
				:default
			else
				:dissect
			end
	end

	# Switches inspect styles in a round-robin fashion between 
	# :dissect, :default, and :hex
	def toggle_inspect
		case @inspect_style
		when :hex, :pretty
			@inspect_style = :dissect
		when :dissect, :verbose
			@inspect_style = :default
		when :default, :ugly
			@inspect_style = :hex
		else
			@inspect_style = :dissect
		end
	end


end

require File.join(cwd,"packetfu","version")
require File.join(cwd,"packetfu","pcap")
require File.join(cwd,"packetfu","packet")
PacketFu.require_protos(cwd)
require File.join(cwd,"packetfu","utils")
require File.join(cwd,"packetfu","config")

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
