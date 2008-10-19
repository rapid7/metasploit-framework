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
	require "rex/socket"
	
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

			# Preparing the packet for building
			self.pre_build()

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
		# e.g. allows TCP(:proto=>'ICMP')
		def from_human(value)
			return value
		end

		# Converts from internal encoding to human display
		# e.g. displays "0xDEADBEEF" for checksums
		def to_human(value)
			return value.to_s
		end

		# Same as to_human() but displays more information
		# e.g. "6 (TCP)" instead of "6" for IP protocol
		def to_human_complete(value)
			return value.to_s
		end

		# Returns yes if the field is to be added to the dissectors, e.g. depending
		# on the value of another field of the layer (see Dot11*)
		def is_applicable?(layer)
			return true
		end

		# Prepares the packet for building
		# e.g. for StrLenField, retrieves the right format size from the associated FieldLenField
		def pre_build
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

	# Shortcut mixins for reducing code size
	module FieldHumanHexEnum
		def to_human(value)
			return sprintf('0x%x', value)
		end

		def to_human_complete(value)
			# Checking if the value is in the enumeration keys
			if @enum.keys.include?(value)
				return sprintf('0x%x', value) + ' (' + @enum[value].to_s + ')'

			# Otherwise, just returning the value
			else
				return sprintf('0x%x', value)
			end
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
			puts "ok"
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

			@@bitsdone ||= 0
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
		
			@@bitsdone ||= 0
			
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
		include FieldHumanHexEnum
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
		include FieldHumanHexEnum
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
		include FieldHumanHexEnum
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
		include FieldHumanHexEnum
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
		include FieldHumanHexEnum
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
		include FieldHumanHexEnum
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
			ip = Rex::Socket.resolv_nbo(name)
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

	# Field for a set of flags (e.g. each bit has a label)
	class FlagsField<BitField

		def initialize(name, default_value, size, flags)
			@name = name
			@default_value = default_value
			@format = 'B'
			@flags = flags

			# Number of bits in the field
			@size = size

			# Number of bits processed so far within the current byte (class/static variable)
			@@bitsdone = 0

			# Byte being processed (class/static variable)
			@@byte = 0
		end

		def from_human(value)

			return value if not value.is_a?(String)

			# Run through the flags and set the corresponding bit if it matches
			out = 0
			@flags.length.times do |index|
				out |= 2**index if value.include?(@flags[index])
			end

			return out
		end

		def to_human_complete(value)

			loops = 0
			out = ''

			begin
				bit = value & (2**loops)
				out = @flags[loops] + ' ' + out if bit != 0
				loops += 1
			end until loops == @size

			# Removing the last space
			out = out[0, out.length - 1] if out.length > 0

			return value.to_s + ' (' + out + ')'
		end

	end

	# Field for one long (big endian/network order)
	class LongField<Field
		def init
			@format = 'Q'
		end
	end

	# Same as LongField, displayed in hexadecimal form
	class XLongField<LongField
		include FieldHumanHex
	end

	# Field for one long (big endian/network order) with enumeration
	class LongEnumField<EnumField
		def init
			@format = 'n'
		end
	end

	# Same as LongEnumField, displayed in hexadecimal form
	class XLongEnumField<LongEnumField
		include FieldHumanHexEnum
	end

	# Field that holds the length of a subsequent field
	class FieldLenField<IntField

		def initialize(name, default_value, length_of, format, opts={})
			@name = name
			@default_value = default_value
			@format = format
			@length_of = length_of
			@opts = opts

			# Length of the other field (class/static variable)
			@@length = {}

			# Saving the size of the associated field
			@@length[@length_of] = @default_value		
		end

		def from_net(value)
			@opts ||= {}
			value[0] = (value[0].to_i + @opts[:adjust].to_i)
			
			# Saving the size of the associated field
			@@length[@length_of] = value[0]
		end

		def to_net(value)
			@opts ||= {}
			# value -= @opts[:adjust].to_i
			
			[ value ].pack(@format)
		end
	end

	# Field holding a string whose size is given by a previous FieldLenField
	# NB : in Scapy, the third field is a lambda-function indicating how to compute the value.
	# This is not implemented in Scruby yet.
	class StrLenField<FieldLenField

		def initialize(name, default_value, length_from)
			@name = name
			@default_value = default_value
			@length_from = length_from
			@size = @@length[name]
			@format = 'a' + @size.to_s
		end

		def pre_build
			@size = @@length[@name]
			@format = 'a' + @size.to_s
		end

		def to_net(value)
			
			@size = @@length[@name]
			@format = 'a' + @size.to_s

			# By default, value is ''
			if value
				return value[0, @size].to_s
			else
				return ''
			end
		end
		
		def from_net(value)
			value[0]
		end

		def to_human(value)
			return value.inspect
		end

		def to_human_complete(value)
			return value.inspect
		end

	end

	# NB for Dot11* fields: 
	# These functions have different 'is_applicable?' methods, to build different
	# kinds of packets with the same dissector, depending on its type.
	# http://trac.secdev.org/scapy/ticket/4 (second point)
	# http://sss-mag.com/pdf/802_11tut.pdf

	# Field for a 802.11 address field
	class Dot11AddrMACField<MACField
	end

	# Field for a 802.11 address field #2
	class Dot11Addr2MACField<MACField
		def is_applicable?(layer)
			if layer.type == DOT11TYPE_CONTROL
				should = [DOT11SUBTYPE_PS_POLL, DOT11SUBTYPE_RTS, DOT11SUBTYPE_CF_END, DOT11SUBTYPE_CF_END_CF_ACK]
				return should.include?(layer.subtype)
			else
				return true
			end
		end
	end

	# Field for a 802.11 address field #3 
	class Dot11Addr3MACField<MACField
		def is_applicable?(layer)
			return true if layer.type == DOT11TYPE_MANAGEMENT or layer.type == DOT11TYPE_DATA
			return false
		end
	end

	# Field for a 802.11 address field #4
	class Dot11Addr4MACField<MACField
		def is_applicable?(layer)
			return true if layer.type == DOT11TYPE_DATA and layer.FCfield & 0x3 == 0x3
			return false
		end
	end

	# Field for a 802.11 SC field
	class Dot11SCField<LEShortField
		def is_applicable?(layer)
			return layer.type != DOT11TYPE_CONTROL
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
	BitFieldLenField
	CharEnumField
	DHCPOptionsField
	DNSQRField
	DNSRRCountField
	DNSRRField
	DNSStrField
	DestMACField
	FieldListField
	IPoptionsField
	ISAKMPTransformSetField
	LEFieldLenField
	LELongField
	LESignedIntField
	LenField
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
	StrNullField
	StrStopField
	TCPOptionsField
	TimeStampField
	X3BytesField
	XBitField
	XLongField

=end