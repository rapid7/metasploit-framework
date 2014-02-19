#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'

module Metasm
# BFLT is the binary flat format used by the uClinux
# from examining a v4 binary, it looks like the header is discarded and the file is mapped from 0x40 to memory address 0 (wrt relocations)
class Bflt < ExeFormat
  MAGIC = 'bFLT'
  FLAGS = { 1 => 'RAM', 2 => 'GOTPIC', 4 => 'GZIP' }

  attr_accessor :header, :text, :data, :reloc, :got

  class Header < SerialStruct
    mem :magic, 4
    words :rev, :entry, :data_start, :data_end, :bss_end, :stack_size,
      :reloc_start, :reloc_count, :flags
    mem :pad, 6*4
    fld_bits(:flags, FLAGS)

    def decode(exe)
      super(exe)

      case @magic
      when MAGIC
      else raise InvalidExeFormat, "Bad bFLT signature #@magic"
      end

      if @rev >= 0x01000000 and (@rev & 0x00f0ffff) == 0
        puts "Bflt: probable wrong endianness, retrying" if $VERBOSE
        exe.endianness = { :big => :little, :little => :big }[exe.endianness]
        exe.encoded.ptr -= 4*16
        super(exe)
      end
    end

    def set_default_values(exe)
      @magic ||= MAGIC
      @rev ||= 4
      @entry ||= 0x40
      @data_start ||= 0x40 + exe.text.length if exe.text
      @data_end ||= @data_start + exe.data.data.length if exe.data
      @bss_end ||= @data_start + exe.data.length if exe.data
      @stack_size ||= 0x1000
      @reloc_start ||= @data_end
      @reloc_count ||= exe.reloc.length
      @flags ||= []

      super(exe)
    end
  end

  def decode_word(edata = @encoded) edata.decode_imm(:u32, @endianness) end
  def encode_word(w) Expression[w].encode(:u32, @endianness) end

  attr_accessor :endianness
  def initialize(cpu = nil)
    @endianness = cpu ? cpu.endianness : :little
    @header = Header.new
    @text = EncodedData.new
    @data = EncodedData.new
    super(cpu)
  end

  def decode_header
    @encoded.ptr = 0
    @header.decode(self)
    @encoded.add_export(new_label('entrypoint'), @header.entry)
  end

  def decode
    decode_header

    @text = @encoded[0x40...@header.data_start]
    @data = @encoded[@header.data_start...@header.data_end]
    @data.virtsize += @header.bss_end - @header.data_end

    if @header.flags.include?('GZIP')
      # TODO gzip
      raise 'bFLT decoder: gzip format not supported'
    end

    @reloc = []
    @encoded.ptr = @header.reloc_start
    @header.reloc_count.times { @reloc << decode_word }
    if @header.rev == 2
      @reloc.map! { |r| r & 0x3fff_ffff }
    end

    decode_interpret_relocs
  end

  def decode_interpret_relocs
    textsz = @header.data_start-0x40
    @reloc.each { |r|
      # where the reloc is
      if r < textsz
        section = @text
        off = section.ptr = r
      else
        section = @data
        off = section.ptr = r-textsz
      end

      # what it points to
      target = decode_word(section)
      if target < textsz
        target = label_at(@text, target, "xref_#{Expression[target]}")
      elsif target < @header.bss_end-0x40
        target = label_at(@data, target-textsz, "xref_#{Expression[target]}")
      else
        puts "out of bounds reloc target #{Expression[target]} at #{Expression[r]}" if $VERBOSE
        next
      end

      section.reloc[off] = Relocation.new(Expression[target], :u32, @endianness)
    }
  end

  def encode
    create_relocation_table

    # TODO got, gzip
    if @header.flags.include? 'GZIP'
      puts "W: bFLT: clearing gzip flag" if $VERBOSE
      @header.flags.delete 'GZIP'
    end

    @encoded = EncodedData.new
    @encoded << @header.encode(self)

    binding = @text.binding(0x40).merge(@data.binding(@header.data_start))
    @encoded << @text << @data.data
    @encoded.fixup! binding
    @encoded.reloc.clear

    @relocs.each { |r| @encoded << encode_word(r) }

    @encoded.data
  end

  def create_relocation_table
    @reloc = []
    mapaddr = new_label('mapaddr')
    binding = @text.binding(mapaddr).merge(@data.binding(mapaddr))
    [@text, @data].each { |section|
      base = 0x40	# XXX maybe 0 ?
      base = @header.data_start || base+@text.length if section == @data
      section.reloc.each { |o, r|
        if r.endianness == @endianness and [:u32, :a32, :i32].include? r.type and
            Expression[r.target.bind(binding), :-, mapaddr].reduce.kind_of? ::Integer
          @reloc << (base+o)
        else
          puts "bFLT: ignoring unsupported reloc #{r.inspect} at #{Expression[o]}" if $VERBOSE
        end
      }
    }
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
      @header.entry = entrypoint
    else super(instr)
    end
  end

  def assemble(*a)
    parse(*a) if not a.empty?
    @text << assemble_sequence(@textsrc, @cpu)
    @textsrc.clear
    @data << assemble_sequence(@datasrc, @cpu)
    @datasrc.clear
    self
  end

  def get_default_entrypoints
    ['entrypoint']
  end

  def each_section
    yield @text, 0
    yield @data, @header.data_start - @header.entry
  end

  def section_info
    [['.text', 0, @text.length, 'rx'],
     ['.data', @header.data_addr-0x40, @data.data.length, 'rw'],
     ['.bss',  @header.data_end-0x40,  @data.length-@data.data.length, 'rw']]
  end

  def module_symbols
    ['entrypoint', @header.entry-0x40]
  end
end
end
