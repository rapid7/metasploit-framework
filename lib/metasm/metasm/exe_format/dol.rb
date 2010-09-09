#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'

module Metasm
class Dol < ExeFormat
	attr_accessor :header, :text, :data

	class Header < SerialStruct
		7.times  { |i| word "foff_text#{i}".to_sym }
		11.times { |i| word "foff_data#{i}".to_sym }
		7.times  { |i| word "addr_text#{i}".to_sym }
		11.times { |i| word "addr_data#{i}".to_sym }
		7.times  { |i| word "size_text#{i}".to_sym }
		11.times { |i| word "size_data#{i}".to_sym }
		word :addr_bss
		word :size_bss
		word :entrypoint
		mem :pad, 0x100-0xe4
	end

	def decode_word(edata = @encoded) edata.decode_imm(:u32, @endianness) end
	def encode_word(w) Expression[w].encode(:u32, @endianness) end

	def initialize(cpu = nil)
		@endianness = :big
		@header = Header.new
		@text = []
		@data = []
		super(cpu)
	end

	def decode_header
		@encoded.ptr = 0
		@header.decode(self)
	end

	def decode
		decode_header

		7.times { |i|
			off = @header.send("foff_text#{i}")
			sz  = @header.send("size_text#{i}")
			@text << @encoded[off, sz]
		}
		11.times { |i|
			off = @header.send("foff_data#{i}")
			sz  = @header.send("size_data#{i}")
			@data << @encoded[off, sz]
		}
	end

	def encode(ignored=nil)
		binding = {}
		addr = 0	# XXX
		@encoded = EncodedData.new
		@text.each_with_index { |s, i|
			next if not s
			@header.send("foff_text#{i}=", new_label("foff_text#{i}"))
			@header.send("size_text#{i}=", new_label("size_text#{i}"))
			@header.send("addr_text#{i}=", new_label("addr_text#{i}")) if not @header.send("addr_text#{i}")
		}
		@data.each_with_index { |s, i|
			next if not s
			@header.send("foff_data#{i}=", new_label("foff_data#{i}"))
			@header.send("size_data#{i}=", new_label("size_data#{i}"))
			@header.send("addr_data#{i}=", new_label("addr_data#{i}")) if not @header.send("addr_data#{i}")
		}
		@encoded << @header.encode(self)

		@text.each_with_index { |s, i|
			next if not s
			binding[@header.send("foff_text#{i}")] = @encoded.length
			binding[@header.send("size_text#{i}")] = s.length
			binding[@header.send("addr_text#{i}")] = addr if @header.send("addr_text#{i}").kind_of? String
			binding.update s.binding(addr)
			@encoded << s
			addr += s.length
		}
		@data.each_with_index { |s, i|
			next if not s
			binding[@header.send("foff_data#{i}")] = @encoded.length
			binding[@header.send("size_data#{i}")] = s.length
			binding[@header.send("addr_data#{i}")] = addr if @header.send("addr_data#{i}").kind_of? String
			binding.update s.binding(addr)
			@encoded << s
			addr += s.length
		}
		@encoded.fixup! binding
		@encoded.data
	end

	def parse_init
		@textsrc ||= []
		@datasrc ||= []
		@cursource ||= @textsrc
		super()
	end

	def parse_parser_instruction(instr)
		case instr.raw.downcase
		when '.text'; @cursource = @textsrc
		when '.data'; @cursource = @datasrc
		when '.entrypoint'
			# ".entrypoint <somelabel/expression>" or ".entrypoint" (here)
			@lexer.skip_space
			if tok = @lexer.nexttok and tok.type == :string
				raise instr if not entrypoint = Expression.parse(@lexer)
			else
				entrypoint = new_label('entrypoint')
				@cursource << Label.new(entrypoint, instr.backtrace.dup)
			end
			@header.entrypoint = entrypoint
		else super(instr)
		end
	end

	def assemble(*a)
		parse(*a) if not a.empty?
		@text[0] ||= EncodedData.new
		@text[0] << assemble_sequence(@textsrc, @cpu)
		@textsrc.clear
		@data[0] ||= EncodedData.new
		@data[0] << assemble_sequence(@datasrc, @cpu)
		@datasrc.clear
		self
	end

	def each_section
		7.times { |i|
			next if not @text[i]
			yield @text[i], instance_variable_get("addr_text#{i}")
		}
		11.times { |i|
			next if not @data[i]
			yield @data[i], instance_variable_get("addr_data#{i}")
		}
	end
end
end
