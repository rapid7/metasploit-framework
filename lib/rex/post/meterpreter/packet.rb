#!/usr/bin/env ruby

module Rex
module Post
module Meterpreter

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
# TLV base starting points
#
TLV_RESERVED                = 0
TLV_EXTENSIONS              = 20000
TLV_USER                    = 40000
TLV_TEMP                    = 60000

#
# TLV Specific Types
#
TLV_TYPE_ANY                = TLV_META_TYPE_NONE   |   0
TLV_TYPE_METHOD             = TLV_META_TYPE_STRING |   1
TLV_TYPE_REQUEST_ID         = TLV_META_TYPE_STRING |   2
TLV_TYPE_EXCEPTION          = TLV_META_TYPE_GROUP  |   3
TLV_TYPE_RESULT             = TLV_META_TYPE_UINT   |   4

TLV_TYPE_STRING             = TLV_META_TYPE_STRING |  10
TLV_TYPE_UINT               = TLV_META_TYPE_UINT   |  11
TLV_TYPE_BOOL               = TLV_META_TYPE_BOOL   |  12

TLV_TYPE_LENGTH             = TLV_META_TYPE_UINT   |  25
TLV_TYPE_DATA               = TLV_META_TYPE_RAW    |  26
TLV_TYPE_FLAGS              = TLV_META_TYPE_UINT   |  27

TLV_TYPE_CHANNEL_ID         = TLV_META_TYPE_UINT   |  50
TLV_TYPE_CHANNEL_TYPE       = TLV_META_TYPE_STRING |  51
TLV_TYPE_CHANNEL_DATA       = TLV_META_TYPE_RAW    |  52
TLV_TYPE_CHANNEL_DATA_GROUP = TLV_META_TYPE_GROUP  |  53
TLV_TYPE_CHANNEL_CLASS      = TLV_META_TYPE_UINT   |  54

TLV_TYPE_SEEK_WHENCE        = TLV_META_TYPE_UINT   |  70
TLV_TYPE_SEEK_OFFSET        = TLV_META_TYPE_UINT   |  71
TLV_TYPE_SEEK_POS           = TLV_META_TYPE_UINT   |  72

TLV_TYPE_EXCEPTION_CODE     = TLV_META_TYPE_UINT   | 300
TLV_TYPE_EXCEPTION_STRING   = TLV_META_TYPE_STRING | 301

TLV_TYPE_LIBRARY_PATH       = TLV_META_TYPE_STRING | 400
TLV_TYPE_TARGET_PATH        = TLV_META_TYPE_STRING | 401
TLV_TYPE_MIGRATE_PID        = TLV_META_TYPE_UINT   | 402
TLV_TYPE_MIGRATE_LEN        = TLV_META_TYPE_UINT   | 403
TLV_TYPE_MIGRATE_PAYLOAD    = TLV_META_TYPE_STRING | 404

TLV_TYPE_CIPHER_NAME        = TLV_META_TYPE_STRING | 500
TLV_TYPE_CIPHER_PARAMETERS  = TLV_META_TYPE_GROUP  | 501

#
# Core flags
#
LOAD_LIBRARY_FLAG_ON_DISK   = (1 << 0)
LOAD_LIBRARY_FLAG_EXTENSION = (1 << 1)
LOAD_LIBRARY_FLAG_LOCAL     = (1 << 2)

###
#
# Base TLV (Type-Length-Value) class
#
###
class Tlv
	attr_accessor :type, :value

	## 
	#
	# Constructor
	#
	##

	#
	# Returns an instance of a TLV. 
	#
	def initialize(type, value = nil)
		@type  = type
		
		if (value != nil)
			if (type & TLV_META_TYPE_STRING == TLV_META_TYPE_STRING)
				if (value.kind_of?(Fixnum))
					@value = value.to_s
				else
					@value = value.dup
				end
			else
				@value = value
			end
		end
	end

	##
	#
	# Conditionals
	#
	##

	#
	# Checks to see if a TLVs meta type is equivalent to the meta type passed.
	#
	def meta_type?(meta)
		return (self.type & meta == meta)
	end

	#
	# Checks to see if the TLVs type is equivalent to the type passed.
	#
	def type?(type)
		return self.type == type
	end

	#
	# Checks to see if the TLVs value is equivalent to the value passed.
	#
	def value?(value)
		return self.value == value
	end

	##
	#
	# Serializers
	#
	##

	#
	# Converts the TLV to raw.
	#
	def to_r
		raw = value.to_s;

		if (self.type & TLV_META_TYPE_STRING == TLV_META_TYPE_STRING)
			raw += "\x00"
		elsif (self.type & TLV_META_TYPE_UINT == TLV_META_TYPE_UINT)
			raw = [value].pack("N")
		elsif (self.type & TLV_META_TYPE_BOOL == TLV_META_TYPE_BOOL)
			if (value == true)
				raw = [1].pack("c")
			else
				raw = [0].pack("c")
			end
		end

		return [raw.length + 8, self.type].pack("NN") + raw
	end

	#
	# Translates the raw format of the TLV into a sanitize version.
	#
	def from_r(raw)
		self.value  = nil

		length, self.type = raw.unpack("NN");

		if (self.type & TLV_META_TYPE_STRING == TLV_META_TYPE_STRING)
			if (raw.length > 0)
				self.value = raw[8..length-2]
			else
				self.value = nil
			end
		elsif (self.type & TLV_META_TYPE_UINT == TLV_META_TYPE_UINT)
			self.value = raw.unpack("NNN")[2]
		elsif (self.type & TLV_META_TYPE_BOOL == TLV_META_TYPE_BOOL)
			self.value = raw.unpack("NNc")[2]

			if (self.value == 1)
				self.value = true
			else
				self.value = false
			end
		else
			self.value = raw[8..length-1]
		end

		return length;
	end
end

###
#
# Group TLVs contain zero or more TLVs
#
###
class GroupTlv < Tlv
	attr_accessor :tlvs

	##
	#
	# Constructor
	#
	##

	#
	# Initializes the group TLV container to the supplied type
	# and creates an empty TLV array.
	#
	def initialize(type)
		super(type)

		self.tlvs = [ ]
	end

	##
	#
	# Group-based TLV accessors
	#
	##

	#
	# Enumerates TLVs of the supplied type.
	#
	def each(type = TLV_TYPE_ANY, &block)
		get_tlvs(type).each(&block)
	end

	#
	# Synonym for each.
	#
	def each_tlv(type = TLV_TYPE_ANY, &block)
		each(type, block)
	end

	#
	# Enumerates TLVs of a supplied type with indexes.
	#
	def each_with_index(type = TLV_TYPE_ANY, &block)
		get_tlvs(type).each_with_index(&block)
	end

	#
	# Synonym for each_with_index.
	#
	def each_tlv_with_index(type = TLV_TYPE_ANY, &block)
		each_with_index(type, block)
	end

	#
	# Returns an array of TLVs for the given type.
	#
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

	##
	#
	# TLV management
	#
	##

	#
	# Adds a TLV of a given type and value.
	#
	def add_tlv(type, value = nil, replace = false)
		tlv = nil

		# If we should replace any TLVs with the same type...remove them first
		if (replace)
			each(type) { |tlv|
				if (tlv.type == type)
					self.tlvs.delete(tlv)
				end
			}
		end

		if (type & TLV_META_TYPE_GROUP == TLV_META_TYPE_GROUP)
			tlv = GroupTlv.new(type)
		else
			tlv = Tlv.new(type, value)
		end

		self.tlvs << tlv

		return tlv
	end

	#
	# Adds zero or more TLVs to the packet.
	#
	def add_tlvs(tlvs)
		if (tlvs != nil)
			tlvs.each { |tlv|
				add_tlv(tlv['type'], tlv['value'])
			}
		end
	end

	#
	# Gets the first TLV of a given type.
	#
	def get_tlv(type, index = 0)
		type_tlvs = get_tlvs(type)

		if (type_tlvs.length > index)
			return type_tlvs[index]
		end

		return nil
	end

	#
	# Returns the value of a TLV if it exists, otherwise nil.
	#
	def get_tlv_value(type, index = 0)
		tlv = get_tlv(type, index)

		return (tlv != nil) ? tlv.value : nil
	end

	#
	# Returns an array of values for all tlvs of type type.
	#
	def get_tlv_values(type)
		get_tlvs(type).collect { |a| a.value }
	end

	#
	# Checks to see if the container has a TLV of a given type.
	#
	def has_tlv?(type)
		return get_tlv(type) != nil
	end

	#
	# Zeros out the array of TLVs.
	#
	def reset
		self.tlvs = []
	end

	##
	#
	# Serializers
	#
	##

	#
	# Converts all of the TLVs in the TLV array to raw and prefixes them
	# with a container TLV of this instance's TLV type.
	#
	def to_r
		raw = ''

		self.each() { |tlv|
			raw << tlv.to_r
		}

		return [raw.length + 8, self.type].pack("NN") + raw
	end

	#
	# Converts the TLV group container from raw to all of the individual
	# TLVs.
	#
	def from_r(raw)
		offset = 8

		# Reset the TLVs array
		self.tlvs = []
		self.type = raw.unpack("NN")[1]

		# Enumerate all of the TLVs
		while (offset < raw.length-1)

			tlv = nil

			# Get the length and type
			length, type = raw[offset..offset+8].unpack("NN")

			if (type & TLV_META_TYPE_GROUP == TLV_META_TYPE_GROUP)
				tlv = GroupTlv.new(type)
			else
				tlv = Tlv.new(type)
			end

			tlv.from_r(raw[offset..offset+length])

			# Insert it into the list of TLVs
			tlvs << tlv

			# Move up
			offset += length
		end
	end

end

###
#
# The logical meterpreter packet class
#
###
class Packet < GroupTlv

	##
	#
	# Factory
	#
	##

	#
	# Creates a request with the supplied method.
	#
	def Packet.create_request(method = nil)
		return Packet.new(PACKET_TYPE_REQUEST, method)
	end

	#
	# Creates a response to a request if one is provided.
	#
	def Packet.create_response(request = nil)
		response_type = PACKET_TYPE_RESPONSE
		method = nil

		if (request)
			if (request.type?(PACKET_TYPE_PLAIN_REQUEST))	
				response_type = PACKET_TYPE_PLAIN_RESPONSE
			end

			method = request.method
		end

		return Packet.new(response_type, method)
	end

	##
	#
	# Constructor
	#
	##

	#
	# Initializes the packet to the supplied packet type and method,
	# if any.  If the packet is a request, a request identifier is 
	# created.
	#
	def initialize(type = nil, method = nil)
		super(type)

		if (method)
			self.method = method
		end

		# If it's a request, generate a random request identifier
		if ((type == PACKET_TYPE_REQUEST) ||
		    (type == PACKET_TYPE_PLAINTEXT_REQUEST))
			rid = ''

			32.times { |val| rid << rand(10).to_s }

			add_tlv(TLV_TYPE_REQUEST_ID, rid)
		end
	end

	##
	#
	# Conditionals
	#
	##

	#
	# Checks to see if the packet is a response.
	#
	def response?
		return ((self.type == PACKET_TYPE_RESPONSE) ||
		        (self.type == PACKET_TYPE_PLAIN_RESPONSE))
	end

	##
	#
	# Accessors
	#
	##

	#
	# Checks to see if the packet's method is equal to the supplied method.
	#
	def method?(method)
		return (get_tlv_value(TLV_TYPE_METHOD) == method)
	end

	#
	# Sets the packet's method TLV to the method supplied.
	#
	def method=(method)
		add_tlv(TLV_TYPE_METHOD, method, true)
	end

	#
	# Returns the value of the packet's method TLV.
	#
	def method
		return get_tlv_value(TLV_TYPE_METHOD)
	end

	#
	# Checks to see if the packet's result value is equal to the supplied
	# result.
	#
	def result?(result)
		return (get_tlv_value(TLV_TYPE_RESULT) == result)
	end

	#
	# Sets the packet's result TLV.
	#
	def result=(result)
		add_tlv(TLV_TYPE_RESULT, result, true)
	end

	#
	# Gets the value of the packet's result TLV.
	#
	def result
		return get_tlv_value(TLV_TYPE_RESULT)
	end

	#	
	# Gets the value of the packet's request identifier TLV.
	#
	def rid
		return get_tlv_value(TLV_TYPE_REQUEST_ID)
	end
end

end; end; end
