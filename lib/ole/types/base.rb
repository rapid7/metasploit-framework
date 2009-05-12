require 'iconv'
require 'date'

require 'ole/base'

module Ole # :nodoc:
	#
	# The Types module contains all the serialization and deserialization code for standard ole
	# types.
	#
	# It also defines all the variant type constants, and symbolic names.
	#
	module Types
		# for anything that we don't have serialization code for
		class Data < String
			def self.load str
				new str
			end
			
			def self.dump str
				str.to_s
			end
		end

		class Lpstr < String
			def self.load str
				# not sure if its always there, but there is often a trailing
				# null byte.
				new str.chomp(0.chr)
			end

			def self.dump str
				# do i need to append the null byte?
				str.to_s
			end
		end

		# for VT_LPWSTR
		class Lpwstr < String
			#FROM_UTF16 = Iconv.new 'utf-8', 'utf-16le'
			#TO_UTF16   = Iconv.new 'utf-16le', 'utf-8'
			
			def self.load str
				new str.unpack('v*').pack('C*').chomp(0.chr) #FROM_UTF16.iconv(str).chomp(0.chr)
			end
			
			def self.dump str
				# need to append nulls?
				data = str.unpack('C*').pack('v*') #TO_UTF16.iconv str
				# not sure if this is the recommended way to do it, but I want to treat
				# the resulting utf16 data as regular bytes, not characters.
				data.force_encoding Encoding::US_ASCII if data.respond_to? :encoding
				data
			end
		end

		# for VT_FILETIME
		class FileTime < DateTime
			SIZE = 8
			EPOCH = new 1601, 1, 1

			# Create a +DateTime+ object from a struct +FILETIME+
			# (http://msdn2.microsoft.com/en-us/library/ms724284.aspx).
			#
			# Converts +str+ to two 32 bit time values, comprising the high and low 32 bits of
			# the 100's of nanoseconds since 1st january 1601 (Epoch).
			def self.load str
				low, high = str.to_s.unpack 'V2'
				# we ignore these, without even warning about it
				return nil if low == 0 and high == 0
				# switched to rational, and fixed the off by 1 second error i sometimes got.
				# time = EPOCH + (high * (1 << 32) + low) / 1e7 / 86400 rescue return
				# use const_get to ensure we can return anything which subclasses this (VT_DATE?)
				const_get('EPOCH') + Rational(high * (1 << 32) + low, 1e7.to_i * 86400) rescue return
				# extra sanity check...
				#unless (1800...2100) === time.year
				#	Log.warn "ignoring unlikely time value #{time.to_s}"
				#	return nil
				#end
				#time
			end
			
			# +time+ should be able to be either a Time, Date, or DateTime.
			def self.dump time
				# i think i'll convert whatever i get to be a datetime, because of
				# the covered range.
				return 0.chr * SIZE unless time
				time = time.send(:to_datetime) if Time === time
				# don't bother to use const_get here
				bignum = (time - EPOCH) * 86400 * 1e7.to_i
				high, low = bignum.divmod 1 << 32
				[low, high].pack 'V2'
			end
			
			def inspect
				"#<#{self.class} #{to_s}>"
			end
		end

		# for VT_CLSID
		# Unlike most of the other conversions, the Guid's are serialized/deserialized by actually
		# doing nothing! (eg, _load & _dump are null ops)
		# Rather, its just a string with a different inspect string, and it includes a
		# helper method for creating a Guid from that readable form (#format).
		class Clsid < String
			SIZE = 16
			PACK = 'V v v CC C6'

			def self.load str
				new str.to_s
			end
			
			def self.dump guid
				return 0.chr * SIZE unless guid
				# allow use of plain strings in place of guids.
				guid['-'] ? parse(guid) : guid
			end
			
			def self.parse str
				vals = str.scan(/[a-f\d]+/i).map(&:hex)
				if vals.length == 5
					# this is pretty ugly
					vals[3] = ('%04x' % vals[3]).scan(/../).map(&:hex)
					vals[4] = ('%012x' % vals[4]).scan(/../).map(&:hex)
					guid = new vals.flatten.pack(PACK)
					return guid if guid.format.delete('{}') == str.downcase.delete('{}')
				end
				raise ArgumentError, 'invalid guid - %p' % str
			end

			def format
				"%08x-%04x-%04x-%02x%02x-#{'%02x' * 6}" % unpack(PACK)
			end
			
			def inspect
				"#<#{self.class}:{#{format}}>"
			end
		end

		#
		# The OLE variant types, extracted from
		# http://www.marin.clara.net/COM/variant_type_definitions.htm.
		#
		# A subset is also in WIN32OLE::VARIANT, but its not cross platform (obviously).
		#
		# Use like:
		#
		#   p Ole::Types::Variant::NAMES[0x001f] => 'VT_LPWSTR'
		#   p Ole::Types::VT_DATE # => 7
		#
		# The serialization / deserialization functions should be fixed to make it easier
		# to work with. like
		#
		#   Ole::Types.from_str(VT_DATE, data) # and
		#   Ole::Types.to_str(VT_DATE, data)
		#
		# Or similar, rather than having to do VT_* <=> ad hoc class name etc as it is
		# currently.
		#
		module Variant
			NAMES = {
				0x0000 => 'VT_EMPTY',
				0x0001 => 'VT_NULL',
				0x0002 => 'VT_I2',
				0x0003 => 'VT_I4',
				0x0004 => 'VT_R4',
				0x0005 => 'VT_R8',
				0x0006 => 'VT_CY',
				0x0007 => 'VT_DATE',
				0x0008 => 'VT_BSTR',
				0x0009 => 'VT_DISPATCH',
				0x000a => 'VT_ERROR',
				0x000b => 'VT_BOOL',
				0x000c => 'VT_VARIANT',
				0x000d => 'VT_UNKNOWN',
				0x000e => 'VT_DECIMAL',
				0x0010 => 'VT_I1',
				0x0011 => 'VT_UI1',
				0x0012 => 'VT_UI2',
				0x0013 => 'VT_UI4',
				0x0014 => 'VT_I8',
				0x0015 => 'VT_UI8',
				0x0016 => 'VT_INT',
				0x0017 => 'VT_UINT',
				0x0018 => 'VT_VOID',
				0x0019 => 'VT_HRESULT',
				0x001a => 'VT_PTR',
				0x001b => 'VT_SAFEARRAY',
				0x001c => 'VT_CARRAY',
				0x001d => 'VT_USERDEFINED',
				0x001e => 'VT_LPSTR',
				0x001f => 'VT_LPWSTR',
				0x0040 => 'VT_FILETIME',
				0x0041 => 'VT_BLOB',
				0x0042 => 'VT_STREAM',
				0x0043 => 'VT_STORAGE',
				0x0044 => 'VT_STREAMED_OBJECT',
				0x0045 => 'VT_STORED_OBJECT',
				0x0046 => 'VT_BLOB_OBJECT',
				0x0047 => 'VT_CF',
				0x0048 => 'VT_CLSID',
				0x0fff => 'VT_ILLEGALMASKED',
				0x0fff => 'VT_TYPEMASK',
				0x1000 => 'VT_VECTOR',
				0x2000 => 'VT_ARRAY',
				0x4000 => 'VT_BYREF',
				0x8000 => 'VT_RESERVED',
				0xffff => 'VT_ILLEGAL'
			}

			CLASS_MAP = {
				# haven't seen one of these. wonder if its same as FILETIME?
				#'VT_DATE' => ?,
				'VT_LPSTR' => Lpstr,
				'VT_LPWSTR' => Lpwstr,
				'VT_FILETIME' => FileTime,
				'VT_CLSID' => Clsid
			}

			module Constants
				NAMES.each { |num, name| const_set name, num }
			end
			
			def self.load type, str
				type = NAMES[type] or raise ArgumentError, 'unknown ole type - 0x%04x' % type
				(CLASS_MAP[type] || Data).load str
			end
			
			def self.dump type, variant
				type = NAMES[type] or raise ArgumentError, 'unknown ole type - 0x%04x' % type
				(CLASS_MAP[type] || Data).dump variant
			end
		end

		include Variant::Constants
		
		# deprecated aliases, kept mostly for the benefit of ruby-msg, until
		# i release a new version.
		def self.load_guid str
			Variant.load VT_CLSID, str
		end

		def self.load_time str
			Variant.load VT_FILETIME, str
		end

		#FROM_UTF16 = Lpwstr::FROM_UTF16
		#TO_UTF16 = Lpwstr::TO_UTF16
	end
end

