# -*- coding: binary -*-
module PacketFu

	# InvalidHeader catches all packets that we don't already have a Struct for,
	# or for whatever reason, violates some basic packet rules for other packet 
	# types.
	class InvalidHeader < Struct.new(:body)
		include StructFu

		def initialize(args={})
			args[:body] ||= StructFu::String.new
			super(args[:body])
		end

		# Returns the object in string form.
		def to_s
			self.to_a.map {|x| x.to_s}.join
		end

		# Reads a string to populate the object.
		def read(str)
			force_binary(str)
			return self if str.nil?
			self[:body].read str
			self
		end

	end

	# You probably don't want to write invalid packets on purpose.
	class	InvalidPacket < Packet
		attr_accessor :invalid_header

		# Any packet is potentially an invalid packet
		def self.can_parse?(str)
			true
		end

		def self.layer
			0
		end

		def read(str=nil,args={})
			@invalid_header.read(str)
			self
		end

		def initialize(args={})
			@invalid_header = 	(args[:invalid] || InvalidHeader.new)
			@headers = [@invalid_header]
		end
	end

end # module PacketFu

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
