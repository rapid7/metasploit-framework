#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'


module Metasm
# Android Dalvik executable file format (similar to java .class)
class DEX < ExeFormat
	MAGIC = "dex\n"
	OPTMAGIC = "dey\n"
	DEPSMAGIC = "deps"

	TYPE = { 0x0000 => 'Header', 0x0001 => 'StringId',
		 0x0002 => 'TypeId', 0x0003 => 'ProtoId',
		 0x0004 => 'FieldId', 0x0005 => 'MethodId',
		 0x0006 => 'ClassDef',
		 0x1000 => 'MapList', 0x1001 => 'TypeList',
		 0x1002 => 'AnnotationSetRefList', 0x1003 => 'AnnotationSetItem',
		 0x2000 => 'ClassData', 0x2001 => 'CodeItem',
		 0x2002 => 'StringData', 0x2003 => 'DebugInfoItem',
		 0x2004 => 'AnnotationItem', 0x2005 => 'EncodedArrayItem',
		 0x2006 => 'AnnotationsDirectoryItem' }

	OPT_FLAGS = { 1 => 'VERIFIED', 2 => 'BIG', 4 => 'FIELDS', 8 => 'INVOCATIONS' }

	ACCESSIBILITY_CLASS = { 1 => 'PUBLIC', 0x10 => 'FINAL', 0x20 => 'SUPER',
		0x200 => 'INTERFACE', 0x400 => 'ABSTRACT', 0x2000 => 'ANNOTATION',
		0x4000 => 'ENUM' }

	VISIBILITY = { 0 => 'BUILD', 1 => 'RUNTIME', 2 => 'SYSTEM' }

	OBJ_TYPE = { 0 => 'Byte', 2 => 'Short', 3 => 'Char', 4 => 'Int',
		6 => 'Long', 0x10 => 'Float', 0x11 => 'Double', 0x17 => 'String',
		0x18 => 'Type', 0x19 => 'Field', 0x1a => 'Method', 0x1b => 'Enum',
		0x1c => 'Array', 0x1d => 'Annotation', 0x1e => 'Null',
		0x1f => 'Boolean' }


	class SerialStruct < Metasm::SerialStruct
		new_int_field :u2, :u4, :uleb, :sleb
	end

	class Header < SerialStruct
		mem :sig, 4
		str :ver, 4
		decode_hook { |exe, hdr| raise InvalidExeFormat, "E: invalid DEX signature #{hdr.sig.inspect}" if hdr.sig != MAGIC }
		u4 :checksum
		mem :sha1sum, 20
		u4 :filesz
		u4 :headersz
		u4 :endiantag, 0x12345678
		u4 :linksz
		u4 :linkoff
		u4 :mapoff
		u4 :stringidssz
		u4 :stringidsoff
		u4 :typeidssz
		u4 :typeidsoff
		u4 :protoidssz
		u4 :protoidsoff
		u4 :fieldidssz
		u4 :fieldidsoff
		u4 :methodidssz
		u4 :methodidsoff
		u4 :classdefssz
		u4 :classdefsoff
		u4 :datasz
		u4 :dataoff
	end

	# header added by optimisation pass ?
	class OptHeader < SerialStruct
		mem :sig, 4
		str :ver, 4
		decode_hook { |exe, hdr| raise InvalidExeFormat, "E: invalid DEY signature #{hdr.sig.inspect}" if hdr.sig != OPTMAGIC }
		u4 :dexoff
		u4 :dexsz
		u4 :depsoff
		u4 :depssz
		u4 :auxoff
		u4 :auxsz
		u4 :flags
		u4 :pad

		fld_bits :flags, OPT_FLAGS
	end

	class MapList < SerialStruct
		u4 :sz
		attr_accessor :list

		def decode(exe)
			super(exe)
			@list = (1..@sz).map { MapItem.decode(exe) }
		end
	end

	class MapItem < SerialStruct
		u2 :type
		fld_enum :type, TYPE
		u2 :unused
		u4 :sz
		u4 :off
	end

	class StringId < SerialStruct
		u4 :off
	end

	class StringData < SerialStruct
		uleb :sz
		attr_accessor :str	# array of sz utf8 chars

		def decode(exe)
			super(exe)
			@str = exe.decode_strz
		end
	end

	class TypeId < SerialStruct
		u4 :descridx
	end

	class FieldId < SerialStruct
		u2 :classidx
		u2 :typeidx
		u4 :nameidx
	end

	class MethodId < SerialStruct
		u2 :classidx
		u2 :typeidx
		u4 :nameidx
	end

	class ProtoId < SerialStruct
		u4 :shortyidx
		u4 :returntypeidx
		u4 :parametersoff
	end

	class ClassDef < SerialStruct
		u4 :classidx
		u4 :accessflags
		fld_bits :accessflags, ACCESSIBILITY_CLASS
		u4 :superclassidx
		u4 :interfaceoff
		u4 :sourcefileidx
		u4 :annotationsoff
		u4 :classdataoff
		u4 :staticvaluesoff

		attr_accessor :data
	end

	class ClassData < SerialStruct
		uleb :staticfsz
		uleb :instancefsz
		uleb :directmsz
		uleb :virtualmsz

		attr_accessor :static_fields, :instance_fields,
			:direct_methods, :virtual_methods

		def decode(exe)
			super(exe)

			@static_fields   = (1..@staticfsz).map   { EncodedField.decode(exe) }
			@instance_fields = (1..@instancefsz).map { EncodedField.decode(exe) }
			@direct_methods  = (1..@directmsz).map  { EncodedMethod.decode(exe) }
			@virtual_methods = (1..@virtualmsz).map { EncodedMethod.decode(exe) }
		end
	end

	class EncodedField < SerialStruct
		uleb :fieldid_diff	# this field id - array.previous field id
		uleb :access

		attr_accessor :field
	end

	class EncodedMethod < SerialStruct
		uleb :methodid_diff	# this method id - array.previous method id
		uleb :access
		uleb :codeoff		# offset to CodeItem

		attr_accessor :method, :code, :name
	end

	class TypeItem < SerialStruct
		u2 :typeidx
	end

	class TypeList < SerialStruct
		u4 :sz
		attr_accessor :list

		def decode(exe)
			super(exe)
			@list = (1..@sz).map { TypeItem.decode(exe) }
			exe.decode_u2 if @sz & 1 == 1		# align
		end
	end

	class CodeItem < SerialStruct
		u2 :registerssz
		u2 :inssz
		u2 :outssz
		u2 :triessz
		u4 :debugoff
		u4 :insnssz

		attr_accessor :insns_off, :try_items, :catch_items

		def decode(exe)
			p0 = exe.encoded.ptr
			super(exe)
			@insns_off = exe.encoded.ptr - p0
			exe.encoded.ptr += 2*@insnssz
			return if @triessz <= 0
			exe.decode_u2 if @insnssz & 1 == 1	# align
			@try_items = (1..@triessz).map { Try.decode(exe) }
			stptr = exe.encoded.ptr
			hnr = exe.decode_uleb
			@catch_items = (1..hnr).map { CatchHandler.decode(exe, exe.encoded.ptr - stptr) }
		end
	end

	class Try < SerialStruct
		u4 :startaddr
		u2 :insncount
		u2 :handleroff		# byte offset into the @catch_items structure
	end

	class CatchHandler < SerialStruct
		sleb :size
		attr_accessor :byteoff
		attr_accessor :type_pairs, :catchalloff

		def decode(exe, boff = nil)
			super(exe)

			@byteoff = boff
			@type_pairs = (1..@size.abs).map { CatchTypePair.decode(exe) }
			@catchalloff = exe.decode_uleb if @size <= 0
		end
	end

	class CatchTypePair < SerialStruct
		uleb :typeidx
		uleb :handleroff
	end
	
	class Link < SerialStruct
		# undefined
	end

	class AnnotationDirectoryItem < SerialStruct
		u4 :classannotationsoff
		u4 :fieldssz
		u4 :methodssz
		u4 :parameterssz

		attr_accessor :field, :method, :parameter
		def decode(exe)
			super(exe)
			@field = (1..@fieldssz).map { FieldAnnotationItem.decode(exe) }
			@method = (1..@methodssz).map { MethodAnnotationItem.decode(exe) }
			@parameter = (1..@parameterssz).map { ParameterAnnotationItem.decode(exe) }
		end
	end

	class FieldAnnotationItem < SerialStruct
		u4 :fieldidx
		u4 :annotationsoff
	end

	class MethodAnnotationItem < SerialStruct
		u4 :methodidx
		u4 :annotationsoff
	end

	class ParameterAnnotationItem < SerialStruct
		u4 :methodidx
		u4 :annotationsoff	# off to AnnSetRefList
	end

	class AnnotationSetRefList < SerialStruct
		u4 :sz
		attr_accessor :list

		def decode(exe)
			super(exe)
			@list = (1..@sz).map { AnnotationSetRefItem.decode(exe) }
		end
	end

	class AnnotationSetRefItem < SerialStruct
		u4 :annotationsoff
	end

	class AnnotationSetItem < SerialStruct
		u4 :sz
		attr_accessor :list

		def decode(exe)
			super(exe)
			@list = (1..@sz).map { AnnotationItem.decode(exe) }
		end
	end

	class AnnotationItem < SerialStruct
		byte :visibility
		fld_enum :visibility, VISIBILITY
		attr_accessor :annotation
	end


	attr_accessor :endianness

	def encode_u2(val) Expression[val].encode(:u16, @endianness) end
	def encode_u4(val) Expression[val].encode(:u32, @endianness) end
	def decode_u2(edata = @encoded) edata.decode_imm(:u16, @endianness) end
	def decode_u4(edata = @encoded) edata.decode_imm(:u32, @endianness) end
	def decode_uleb(ed = @encoded, signed=false)
		v = s = 0
		while s < 5*7
			b = ed.read(1).unpack('C').first.to_i
			v |= (b & 0x7f) << s
			break if (b&0x80) == 0
			s += 7
		end
		v = Expression.make_signed(v, s) if signed
		v
	end
	def decode_sleb(ed = @encoded) decode_uleb(ed, true) end
	attr_accessor :header, :strings, :types, :protos, :fields, :methods, :classes

	def initialize(endianness=:little)
		@endianness = endianness
		@encoded = EncodedData.new
		super()
	end

	def decode_header
		@header = Header.decode(self)
	end

	def decode_strings
		@encoded.ptr = @header.stringidsoff
		so = (1..@header.stringidssz).map { StringId.decode(self) }
		@strings = so.map { |s| @encoded.ptr = s.off ; StringData.decode(self).str }
	end

	def decode_types
		@encoded.ptr = @header.typeidsoff
		tl = (1..@header.typeidssz).map { TypeId.decode(self) }
		@types = tl.map { |t| @strings[t.descridx] }	# TODO demangle or something
	end

	def decode_protos
		@encoded.ptr = @header.protoidsoff
		@protos = (1..@header.protoidssz).map { ProtoId.decode(self) }
	end

	def decode_fields
		@encoded.ptr = @header.fieldidsoff
		@fields = (1..@header.fieldidssz).map { FieldId.decode(self) }
	end

	def decode_methods
		@encoded.ptr = @header.methodidsoff
		@methods = (1..@header.methodidssz).map { MethodId.decode(self) }
	end

	def decode_classes
		@encoded.ptr = @header.classdefsoff
		@classes = (1..@header.classdefssz).map { ClassDef.decode(self) }
		@classes.each { |c|
			next if c.classdataoff == 0
			@encoded.ptr = c.classdataoff
			c.data = ClassData.decode(self)
			id = 0
			(c.data.direct_methods + [0] + c.data.virtual_methods).each { |m|
				next id=0 if m == 0
				id += m.methodid_diff
				m.method = @methods[id]
				m.name = @strings[m.method.nameidx]
				@encoded.ptr = m.codeoff
				m.code = CodeItem.decode(self)
				next if @encoded.ptr > @encoded.length
				l = new_label(m.name + '@' + @types[c.classidx])
				@encoded.add_export l, m.codeoff + m.code.insns_off
			}
		}
	end

	def decode
		decode_header
		decode_strings
		decode_types
		decode_protos
		decode_fields
		decode_methods
		decode_classes
	end

	def cpu_from_headers
		Dalvik.new(self)
	end

	def init_disassembler
		dasm = super()
		@classes.each { |c|
			next if not c.data
			(c.data.direct_methods + c.data.virtual_methods).each { |m|
				n = @types[c.classidx] + '->' + m.name
				dasm.comment[m.codeoff+m.code.insns_off] = [n]
			}
		}
		dasm.function[:default] = @cpu.disassembler_default_func
		dasm
	end

	def each_section
		yield @encoded, 0
#		@classes.each { |c|
#			next if not c.data
#			(c.data.direct_methods + c.data.virtual_methods).each { |m|
#				next if not m.code
#				next if not ed = @encoded[m.codeoff+m.code.insns_off, 2*m.code.insnssz]
#				yield ed, ed.export.index(0)
#			}
#		}
	end

	def get_default_entrypoints
		[]
	end
end

class DEY < DEX
	attr_accessor :optheader, :fullencoded
	def decode_header
		@optheader = OptHeader.decode(self)
		@fullencoded = @encoded
		@encoded = @fullencoded[@optheader.dexoff, @optheader.dexsz]
		super
	end
end
end
