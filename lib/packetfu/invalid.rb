
module PacketFu

	# InvalidHeader catches all packets that we don't already have a struct for, or
	# for whatever reason, violates some basic packet rules for other packet types.
	class InvalidHeader < BinData::MultiValue
		rest			:body # No idea how big this will be or what it will look like; it's invalid!
	end

	# You probably don't want to write invalid packets on purpose.
	class InvalidPacket < Packet
	
		attr_accessor :invalid_header
		
		def invalid?; true; end
			
		def initialize(args={})
			@invalid_header = 	(args[:invalid] || InvalidHeader.new)
			@headers = [@invalid_header]
		end
	end

end # module PacketFu