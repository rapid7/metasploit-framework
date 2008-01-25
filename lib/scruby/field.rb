#!/usr/bin/env ruby
# Copyright (C) 2007 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 

module Scruby

	# Trackin fields
	@@fields = {}

	def Scruby.fields
		@@fields
	end
	
	def Scruby.get_field(d)
		@@fields[d]
	end
	
	class Field

	attr_accessor :name
	attr_accessor :default_value
	attr_accessor :format

	# Constructor
	def initialize(name, default_value)
		@name = name
		@default_value = default_value
		@format = ''

		self.init()
		end

		# Field initialization. This function have to be redefined by subclasses.
		def init
		end

		# Retrieves the field value from a string. This may be redefined by subclasses.
		def dissect(layer, string)

			part = string.unpack(self.format + 'a*')

			# Returning if nothing could be unpacked
			return '' if part[-2].nil? or part[-2] == ''

			# Updating the field value
			layer.instance_variable_set("@#{self.name}", self.from_net(part))

			# 'remain' is the last element of the array (unpacking 'a*'),
			# with this command, part doesn't contain 'remain' anymore.
			remain = part.pop

			return remain
		end

		# Converts from network to internal encoding
		# e.g for IP.dst: number 2130706433 -> string "127.0.0.1" (2130706433 = 127*2^24 + 1*2^0)
		def from_net(value)
			return value[0]
		end

		# Converts from internal encoding to network
		# e.g. for IP.dst: string "127.0.0.1"-> number 2130706433
		def to_net(value)
			return [value].pack(@format)
		end

		# Converts from human to internal encoding
		# e.g. allows TCP(:sport=>'http')
		def from_human(value)
			return value
		end

		# Converts from internal encoding to human display
		# e.g. displays "0xDEADBEEF" for checksums
		def to_human(value)
			return value.to_s
		end

		# Same as tuhuman() but displays more information
		# e.g. "6 (TCP)" instead of "6" for IP protocol
		def to_human_complete(value)
			return value.to_s
		end

	end

	# Shortcut mixins for reducing code size
	module FieldHumanHex
		def to_human(value)
			return sprintf('0x%x', value)
		end

		def to_human_complete(value)
			return sprintf('0x%x', value)
		end	
	end
	
	# Shortcut mixins for signed conversion
	module SignedValue
		
		def utosc(val)
			(val > 0x7f) ? ((0x100 - val) * -1) : val
		end
				
		def utoss(val)
			(val > 0x7fff) ? ((0x10000 - val) * -1) : val
		end
		
		def utosl(val)
			(val > 0x7fffffff) ? ((0x100000000 - val) * -1) : val
		end
		
		def from_net(value)
			val = value[0]
			case @format
			when 'V','N'
				utosl(val)
			when 'v','n'
				utoss(val)
			when 'C'
				utosc(val)
			else
				raise "Unsupport format! #{@format}"
			end
		end			
	end
	
	# Field for an enumeration. Don't use this one in your dissectors,
	# use the *EnumFields below instead.
	class EnumField<Field

		def initialize(name, default_value, enum)
		@name = name
		@default_value = default_value
		@enum = enum
		@format = ''

		self.init()
		end

		def to_human_complete(value)

			# Checking if the value is in the enumeration keys
			if @enum.keys.include?(value)
				return value.to_s + ' (' + @enum[value].to_s + ')'

			# Otherwise, just returning the value
			else
				return value.to_s
			end
		end

		def from_human(value)
			# Checking if the value is in the enumeration values
			if @enum.values.include?(value.to_s)
				return @enum.invert[value]

			# Otherwise, just returning the value
			else
				return value
			end
		end

	end

	# Field for a string
	class StrField<Field

		def init
			@format = 'A*'
		end

		def to_net(value)
			return value.to_s
		end

		def to_human(value)
			return value.to_s.inspect
		end

		def to_human_complete(value)
			return value.to_s.inspect
		end

	end

	# Field for a fixed length string
	class StrFixedLenField<StrField

		def initialize(name, default_value, size)
			@name = name
			@default_value = default_value
			@format = 'A' + size.to_s
		end

		def to_net(value)
			return value.to_s
		end

		def to_human(value)
			return value.to_s.inspect
		end

		def to_human_complete(value)
			return value.to_s.inspect
		end

	end

	# Field for a set of bits
	class BitField<Field

		def initialize(name, default_value, size)
			@name = name
			@default_value = default_value
			@format = 'B'

			# Number of bits in the field
			@size = size

			# Number of bits processed so far within the current byte (class/static variable)
			@@bitsdone = 0

			# Byte being processed (class/static variable)
			@@byte = 0
		end

		def dissect(layer, string)

			# Cannot dissect if the wanted size is greater than the length of the string
			# e.g. "IP('A'*7)" should not set frag=65
			return '' if (@@bitsdone + @size)/8  > string.length

			format = self.format + (@@bitsdone + @size).to_s + 'a*'
			part = string.unpack(format)

			# Returning if nothing could be unpacked
			return '' if part[-2].nil? or part[-2] == ''

			# Updating the field value
			layer.instance_variable_set("@#{self.name}", self.from_net(part))

			# Adding the size of the field to the number of bits processed so far
			@@bitsdone += @size

			# If we have just built a byte or more, moving on to the next part of the string
			if @@bitsdone >= 8
				nb_to_be_trimmed = @@bitsdone/8

				# NB : @@bitsdone will not be always 0 after this (e.g. if bitsdone was not 0 mod 8)
				@@bitsdone -= nb_to_be_trimmed*8

				# Getting rid of the nb_to_be_trimmed bytes that have just been processed
				return string[nb_to_be_trimmed..-1]

			# Otherwise, returning the whole string
			else
				return string
			end
		end

		def from_net(value)
			# Removing high-order bits
			bits = value[0]
			bits = bits.to_i(2)
			bits &= (1 << @size) - 1
			return bits
		end

		def to_net(value)
			# OR'ing this value the value the previous ones
			@@byte <<= @size
			@@byte |= value

			# Adding the size of the field to the number of bits processed so far
			@@bitsdone += @size

			to_be_returned = ''

			# If one or more bytes could have been processed
			if @@bitsdone >= 8

				# Getting high-order bytes one by one in a begin...until loop
				begin
				@@bitsdone -= 8
				new_byte = @@byte >> @@bitsdone
				to_be_returned += [new_byte].pack('C')

				# Removing high-order bits
				@@byte &= (1 << @@bitsdone) - 1

				end until @@bitsdone < 8
			end

			return to_be_returned
		end

	end
	
	# Field for one byte
	class ByteField<Field
		def init
			@format = 'C'
		end
	end

	# Same as ByteField, displayed in hexadecimal form
	class XByteField<ByteField
		include FieldHumanHex
	end

	# Field for one byte with enumeration
	class ByteEnumField<EnumField
		def init
			@format = 'C'
		end
	end

	# Same as ByteEnumField, displayed in hexadecimal form
	class XByteEnumField<ByteEnumField
		include FieldHumanHex
	end

	# Field for one short (big endian/network order)
	class ShortField<Field
		def init
			@format = 'n'
		end
	end

	# Same as ShortField, displayed in hexadecimal form
	class XShortField<ShortField
		include FieldHumanHex
	end

	# Field for one short (big endian/network order) with enumeration
	class ShortEnumField<EnumField
		def init
			@format = 'n'
		end
	end

	# Same as ShortEnumField, displayed in hexadecimal form
	class XShortEnumField<ShortEnumField
		include FieldHumanHex
	end

	# Field for a short (little endian order)
	class LEShortField<Field
		def init
			@format = 'v'
		end
	end

	# Same as LEShortField, displayed in hexadecimal form
	class XLEShortField<LEShortField
		include FieldHumanHex
	end

	# Field for one short (little endian order) with enumeration
	class LEShortEnumField<EnumField
		def init
			@format = 'v'
		end
	end

	# Same as LEShortField, displayed in hexadecimal form
	class XLEShortEnumField<LEShortEnumField
		include FieldHumanHex
	end

	# Field for one integer
	class IntField<Field
		def init
			@format = 'N'
		end
	end

	# Same as IntField, displayed in hexadecimal form
	class XIntField<IntField
		include FieldHumanHex
	end

	# Field for an signed integer
	class SignedIntField<Field	
		include SignedValue
		def init
			@format = 'N'
		end
	end
	
	# Field for one integer with enumeration
	class IntEnumField<EnumField
		def init
			@format = 'N'
		end
	end

	# Same as LEIntField, displayed in hexadecimal form
	class XIntEnumField<IntEnumField
		include FieldHumanHex
	end

	# Field for one integer with enumeration
	class SignedIntEnumField<EnumField
		include SignedValue	
		def init
			@format = 'N'
		end
	end
	
	# Field for an unsigned integer (little endian order)
	class LEIntField<Field
		def init
			@format = 'V'
		end
	end
	
	# Same as LEIntField, displayed in hexadecimal form
	class XLEIntField<LEIntField
		include FieldHumanHex
	end

	# Field for an signed integer (little endian order)
	class LESignedIntField<Field	
		include SignedValue
		def init
			@format = 'V'
		end
	end
	
	# Field for one integer with enumeration
	class LEIntEnumField<EnumField
		def init
			@format = 'V'
		end
	end

	# Same as LEIntField, displayed in hexadecimal form
	class XLEIntEnumField<LEIntEnumField
		include FieldHumanHex
	end

	# Field for one integer (host order)
	class HostOrderIntField<IntField
		def init
			@format = 'L'
		end
	end

	# Same as HostOrderIntField, displayed in hexadecimal form
	class XHostOrderIntField<HostOrderIntField
		include FieldHumanHex
	end

	# Field for one integer (host order) with enumeration
	class HostOrderIntEnumField<EnumField

		def init
			@format = 'L'
		end

	end

	# Same as HostOrderIntEnumField, displayed in hexadecimal form
	class XHostOrderIntEnumField<HostOrderIntEnumField
		include FieldHumanHex
	end

	# Field for a float (big endian/network order)
	class FloatField<Field
		def init
			@format = 'g'
		end
	end

	# Field for a float (big endian/network order) with enumeration
	class FloatEnumField<EnumField
		def init
			@format = 'g'
		end
	end

	# Field for a float (little endian order)
	class LEFloatField<Field
		def init
			@format = 'e'
		end
	end

	# Field for a float (little endian order) with enumeration
	class LEFloatEnumField<EnumField
		def init
			@format = 'e'
		end
	end

	# Field for a float (host order)
	class HostOrderFloatField<Field
		def init
			@format = 'f'
		end
	end

	# Field for a float (host order) with enumeration
	class HostOrderFloatEnumField<EnumField
		def init
			@format = 'f'
		end
	end

	# Field for a double float (big endian/network order)
	class DoubleField<Field
		def init
			@format = 'G'
		end
	end

	# Field for a double float (big endian/network order) with enumeration
	class DoubleEnumField<EnumField
		def init
			@format = 'G'
		end
	end

	# Field for a double float (little endian order)
	class LEDoubleField<Field
		def init
			@format = 'E'
		end
	end

	# Field for a double float (little endian order) with enumeration
	class LEDoubleEnumField<EnumField
		def init
			@format = 'E'
		end
	end

	# Field for an IP address
	class IPField<Field
	
		def init
			@format = 'N'
			@ip_addr = nil
		end

		# Ruby equivalent to inet_aton. It takes a hostname or an IP as an argument.
		def inet_aton(name)
			ip = Socket.getaddrinfo(name, nil)[0][3]
			return [IPAddr.new(ip).to_i].pack(@format)
		end

		def to_net(value)

			# Getting the IP address from the server name if needed
			if @ip_addr.nil?
				@ip_addr = inet_aton(value)
			end

			return @ip_addr
		end

		def from_net(value_array)
			return IPAddr.new(value_array[0], Socket::AF_INET).to_s
		end

		def to_human(value)
			return '"' + value.to_s + '"'
		end

	end

	# Field for an MAC address
	class MACField<Field

		def init
			@format = 'H2H2H2H2H2H2'
		end

		def to_net(value)

			# value can be empty (e.g. loopback device)
			if value.nil?
				value = '00:00:00:00:00:00'
			end

			# Get the bytes in an string array
			bytes = value.split(':')

			return bytes.pack(@format)
		end

		def from_net(value_array)
			# value_array is an array containing 7 bytes, only the first 6 are relevant here.
			return value_array[0, 6].join(':')
		end

	end

	# Field for a set of bits with enumeration
	class BitEnumField<BitField

		def initialize(name, default_value, size, enum)
			@name = name
			@default_value = default_value
			@format = 'B'
			@enum = enum

			# Number of bits in the field
			@size = size

			# Number of bits processed so far within the current byte (class/static variable)
			@@bitsdone = 0

			# Byte being processed (class/static variable)
			@@byte = 0
		end

		def to_human_complete(value)

			# Checking if the value is in the enumeration keys
			if @enum.keys.include?(value)
				return value.to_s + ' (' + @enum[value].to_s + ')'
				# Otherwise, just returning the value
			else
				return value.to_s
			end
		end

		def from_human(value)

			# Checking if the value is in the enumeration values
			if @enum.values.include?(value.to_s)
				return @enum.invert[value]
			# Otherwise, just returning the value
			else
				return value
			end
		end

	end


	# Grep out our field list here
	self.constants.grep(/^([a-zA-Z0-9]+)Field$/).each do |f|
		@@fields[f] = eval(f)
	end
end


=begin

Scruby fields that Scapy is missing:
====================================
	DoubleEnumField
	DoubleField
	FloatEnumField
	HostOrderFloatEnumField
	HostOrderFloatField
	HostOrderIntEnumField
	HostOrderIntField
	LEDoubleEnumField
	LEDoubleField
	LEFloatEnumField
	LEFloatField
	XByteEnumField
	XHostOrderIntEnumField
	XHostOrderIntField
	XIntEnumField
	XLEIntEnumField
	XLEIntField
	XLEShortEnumField
	XLEShortField

Scapy (1.2.0.1) fields that Scruby is missing:
==============================================
	ARPSourceMACField
	BCDFloatField
	BitEnumField
	BitFieldLenField
	CharEnumField
	DHCPOptionsField
	DNSQRField
	DNSRRCountField
	DNSRRField
	DNSStrField
	DestMACField
	Dot11Addr2MACField
	Dot11Addr3MACField
	Dot11Addr4MACField
	Dot11AddrMACField
	Dot11SCField
	FieldLenField
	FieldListField
	FlagsField
	IPoptionsField
	ISAKMPTransformSetField
	LEFieldLenField
	LELongField
	LESignedIntField
	LenField
	LongField
	NetBIOSNameField
	PacketField
	PacketLenField
	PacketListField
	RDLenField
	RDataField
	RandField
	SignedIntEnumField
	SignedIntField
	SourceIPField
	SourceMACField
	StrLenField
	StrNullField
	StrStopField
	TCPOptionsField
	TimeStampField
	X3BytesField
	XBitField
	XLongField

=end
