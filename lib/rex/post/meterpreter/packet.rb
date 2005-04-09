#!/usr/bin/ruby

def gen_tlv(meta, spec)
	return meta | spec	
end

#
# Constants
#
PACKET_TYPE_REQUEST         = 0
PACKET_TYPE_RESPONSE        = 1
PACKET_TYPE_PLAIN_REQUEST   = 10
PACKET_TYPE_PLAIN_RESPONSE  = 11

#
# TLV Meta Types
#
TLV_META_TYPE_NONE          = 0
TLV_META_TYPE_STRING        = (1 << 16)
TLV_META_TYPE_UINT          = (1 << 17)
TLV_META_TYPE_RAW           = (1 << 18)
TLV_META_TYPE_BOOL          = (1 << 19)
TLV_META_TYPE_GROUP         = (1 << 30)
TLV_META_TYPE_COMPLEX       = (1 << 31)

#
# TLV Specific Types
#
TLV_TYPE_ANY                = gen_tlv(TLV_META_TYPE_NONE,     0)
TLV_TYPE_METHOD             = gen_tlv(TLV_META_TYPE_STRING,   1)
TLV_TYPE_REQUEST_ID         = gen_tlv(TLV_META_TYPE_STRING,   2)
TLV_TYPE_EXCEPTION          = gen_tlv(TLV_META_TYPE_GROUP,    3)
TLV_TYPE_RESULT             = gen_tlv(TLV_META_TYPE_UINT,     4)

TLV_TYPE_STRING             = gen_tlv(TLV_META_TYPE_STRING,  10)
TLV_TYPE_UINT               = gen_tlv(TLV_META_TYPE_UINT,    11)
TLV_TYPE_BOOL               = gen_tlv(TLV_META_TYPE_BOOL,    12)

TLV_TYPE_LENGTH             = gen_tlv(TLV_META_TYPE_UINT,    25)
TLV_TYPE_DATA               = gen_tlv(TLV_META_TYPE_RAW,     26)
TLV_TYPE_FLAGS              = gen_tlv(TLV_META_TYPE_UINT,    27)

TLV_TYPE_CHANNEL_ID         = gen_tlv(TLV_META_TYPE_UINT,    50)
TLV_TYPE_CHANNEL_TYPE       = gen_tlv(TLV_META_TYPE_STRING,  51)
TLV_TYPE_CHANNEL_DATA       = gen_tlv(TLV_META_TYPE_RAW,     52)
TLV_TYPE_CHANNEL_DATA_GROUP = gen_tlv(TLV_META_TYPE_GROUP,   53)

TLV_TYPE_EXCEPTION_CODE     = gen_tlv(TLV_META_TYPE_UINT,   300)
TLV_TYPE_EXCEPTION_STRING   = gen_tlv(TLV_META_TYPE_STRING, 301)

TLV_TYPE_LIBRARY_PATH       = gen_tlv(TLV_META_TYPE_STRING, 400)
TLV_TYPE_TARGET_PATH        = gen_tlv(TLV_META_TYPE_STRING, 401)

TLV_TYPE_CIPHER_NAME        = gen_tlv(TLV_META_TYPE_STRING, 500)
TLV_TYPE_CIPHER_PARAMETERS  = gen_tlv(TLV_META_TYPE_GROUP,  501)

#
# Core flags
#
LOAD_LIBRARY_FLAG_ON_DISK   = (1 << 0);
LOAD_LIBRARY_FLAG_EXTENSION = (1 << 1);
LOAD_LIBRARY_FLAG_LOCAL     = (1 << 2);

module Rex
module Post
module Meterpreter

#
# Base TLV class
#
class Tlv
	attr_accessor :type, :value

	def initialize(type, value = nil)
		@type  = type
		@value = value
	end

	#
	# Conditionals
	#

	def meta_type?(meta)
		return (self.type & meta == meta)
	end

	def type?(type)
		return self.type == type
	end

	def value?(value)
		return self.value == value
	end

	#
	# Serializers
	#

	# To raw
	def to_r
		raw = value.to_s;

		if (self.type & TLV_META_TYPE_STRING == TLV_META_TYPE_STRING)
			raw << "\x00"
		elsif (self.type & TLV_META_TYPE_UINT == TLV_META_TYPE_UINT)
			raw = [value].pack("N")
		elsif (self.type & TLV_META_TYPE_BOOL == TLV_META_TYPE_BOOL)
			raw = [value].pack("c")
		end

		return [raw.length + 8, self.type].pack("NN") + raw
	end

	# From raw
	def from_r(raw)
		self.value  = nil

		length, type = raw.unpack("NN");

		if (self.type & TLV_META_TYPE_STRING == TLV_META_TYPE_STRING)
			if (raw.length > 0)
				self.value = raw[8..raw.length-1]
			else
				self.value = nil
			end
		elsif (self.type & TLV_META_TYPE_UINT == TLV_META_TYPE_UINT)
			self.value = raw.unpack("NNN")[2]
		elsif (self.type & TLV_META_TYPE_BOOL == TLV_META_TYPE_BOOL)
			self.value = raw.unpack("NNc")[2]
		end

		return length;
	end
end

#
# Group TLVs contain zero or more TLVs
#
class GroupTlv < Tlv
	attr_accessor :tlvs

	def initialize(type)
		super(type)

		self.tlvs = [ ]
	end

	#
	# Group-based TLV accessors
	#

	# Enumerates TLVs of the supplied type
	def each(type = TLV_TYPE_ANY, &block)
		get_tlvs(type).each(&block)
	end

	# Enumerates TLVs of a supplied type with indexes
	def each_with_index(type = TLV_TYPE_ANY, &block)
		get_tlvs(type).each_with_index(&block)
	end

	# Returns an array of TLVs for the given type
	def get_tlvs(type)
		if (type == TLV_TYPE_ANY)
			return self.tlvs
		else
			type_tlvs = []

			self.tlvs.each() { |tlv|
				if (tlv.type?(type))
					type_tlvs << tlv
				end
			}

			return type_tlvs
		end
	end

	#
	# TLV management
	#

	# Adds a TLV of a given type and value
	def add_tlv(type, value = nil)
		tlv = nil

		if (type & TLV_META_TYPE_GROUP == TLV_META_TYPE_GROUP)
			tlv = GroupTlv.new(type)
		else
			tlv = Tlv.new(type, value)
		end

		self.tlvs << tlv

		return tlv
	end

	# Gets the first TLV of a given type
	def get_tlv(type, index = 0)
		type_tlvs = get_tlvs(type)

		if (type_tlvs.length > index)
			return type_tlvs[index]
		end

		return nil
	end

	def reset
		self.tlvs = []
	end

	#
	# Serializers
	#

	# To raw
	def to_r
		raw = ''

		self.each() { |tlv|
			raw << tlv.to_r
		}

		return [raw.length, self.type].pack("NN") + raw
	end

	# From raw
	def from_r(raw)
		offset = 8

		# Reset the TLVs array
		self.tlvs = []

		# Enumerate all of the TLVs
		while (offset < raw.length)

			# Get the length and type
			length, type = raw[offset..offset+8].unpack("NN")

			# Create the TLV and serialize it
			tlv = Tlv.new(type)

			tlv.from_r(raw[offset..offset+length])

			# Insert it into the list of TLVs
			tlvs << tlv

			# Move up
			offset += length
		end
	end

end

#
# The logical meterpreter packet class
#
class Packet < GroupTlv

	#
	# Factory
	#

	# Creates a request with the supplied method
	def Packet.create_request(method = nil)
		return Packet.new(PACKET_TYPE_REQUEST, method)
	end

	# Creates a response to a request if one is provided
	def Packet.create_response(request = nil)
		response_type = PACKET_TYPE_RESPONSE
		method = nil

		if (request)
			if (request.type?(ACKET_TYPE_PLAIN_REQUEST))	
				response_type = PACKET_TYPE_PLAIN_RESPONSE
			end

			method = request.method
		end

		return Packet.new(response_type, method)
	end

	#
	# Constructor
	#

	def initialize(type = nil, method = nil)
		super(type)

		if (method)
			self.method = method
		end
	end

	def type=(type)
		@type = type

		# If it's a request, generate a random request identifier
		if ((type == PACKET_TYPE_REQUEST) ||
		    (type == PACKET_TYPE_RESPONSE))
			rid = ''

			1.upto(32) { |val| rid << rand(10).to_s }

			add_tlv(TLV_TYPE_REQUEST_ID, rid)
		end
	end

	def method?(method)
		return get_tlv(TLV_TYPE_METHOD) == method
	end

	def method=(method)
		add_tlv(TLV_TYPE_METHOD, method)
	end

	def method
		return get_tlv(TLV_TYPE_METHOD)
	end

	def result?(result)
		return get_tlv(TLV_TYPE_RESULT) == result
	end

	def result=(result)
		add_tlv(TLV_TYPE_RESULT, result)
	end

	def result
		return get_tlv(TLV_TYPE_RESULT)
	end

	def rid
		return get_tlv(TLV_TYPE_REQUEST_ID)
	end
end

end; end; end
