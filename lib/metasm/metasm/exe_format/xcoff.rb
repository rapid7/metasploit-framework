#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'

module Metasm
class XCoff < ExeFormat
  FLAGS = { 1 => 'RELFLG', 2 => 'EXEC', 4 => 'LNNO',
    0x200 => 'AR32W', 0x400 => 'PATCH', 0x1000 => 'DYNLOAD',
    0x2000 => 'SHROBJ', 0x4000 => 'LOADONLY' }

  SECTION_FLAGS = { 8 => 'PAD', 0x20 => 'TEXT', 0x40 => 'DATA', 0x80 => 'BSS',
    0x100 => 'EXCEPT', 0x200 => 'INFO', 0x1000 => 'LOADER',
    0x2000 => 'DEBUG', 0x4000 => 'TYPCHK', 0x8000 => 'OVRFLO' }

  class SerialStruct < Metasm::SerialStruct
    new_int_field :xword, :xhalf
  end

  class Header < SerialStruct
    mem :sig, 2
    decode_hook { |exe, hdr|
      exe.endianness, exe.intsize =
      case @sig
      when "\1\xdf"; [:big,    32]
      when "\xdf\1"; [:little, 32]
      when "\1\xef"; [:big,    64]
      when "\xef\1"; [:little, 64]
      else raise InvalidExeFormat, "invalid a.out signature"
      end
    }
    half :nsec
    word :timdat
    xword :symptr
    word :nsym
    half :opthdr
    half :flags
    fld_bits :flags, FLAGS

    def set_default_values(xcoff)
      @sig ||= case [xcoff.endianness, xcoff.intsize]
        when [:big,    32]; "\1\xdf"
        when [:little, 32]; "\xdf\1"
        when [:big,    64]; "\1\xef"
        when [:little, 64]; "\xef\1"
        end
      @nsec   ||= xcoff.sections.size
      @symptr ||= xcoff.symbols ? xcoff.new_label('symptr') : 0
      @nsym   ||= xcoff.symbols ? xcoff.symbols.length : 0
      @opthdr ||= xcoff.optheader ? OptHeader.size(xcoff) : 0
      super(xcoff)
    end
  end

  class OptHeader < SerialStruct
    halfs :magic, :vstamp
    xwords :tsize, :dsize, :bsize, :entry, :text_start, :data_start, :toc
    halfs :snentry, :sntext, :sndata, :sntoc, :snloader, :snbss, :aligntext, :aligndata, :modtype, :cpu
    xwords :maxstack, :maxdata
    new_field(:res, lambda { |exe, me| exe.encoded.read(exe.intsize == 32 ? 8 : 120) }, lambda { |exe, me, val| val }, '')


    def self.size(xcoff)
      xcoff.intsize == 32 ? 2*2+7*4+10*2+2*4+2+8 : 2*2+7*8+10*2+2*8+2+120
    end

    def set_default_values(xcoff)
      @vstamp  ||= 1
      @snentry ||= 1
      @sntext  ||= 1
      @sndata  ||= 2
      @sntoc   ||= 3
      @snloader||= 4
      @snbss   ||= 5
      super(xcoff)
    end
  end

  class Section < SerialStruct
    str :name, 8
    xwords :paddr, :vaddr, :size, :scnptr, :relptr, :lnnoptr
    xhalfs :nreloc, :nlnno, :flags
    fld_bits :flags, SECTION_FLAGS

    def set_defalut_values(xcoff)
      @name   ||= @flags.kind_of?(::Array) ? ".#{@flags.first.to_s.downcase}" : ''
      @vaddr  ||= @paddr ? @paddr : @encoded ? xcoff.label_at(@encoded, 0, 's_vaddr') : 0
      @paddr  ||= @vaddr
      @size   ||= @encoded ? @encoded.size : 0
      @scnptr ||= xcoff.new_label('s_scnptr')
      super(xcoff)
    end
  end

  # basic immediates decoding functions
  def decode_half( edata = @encoded) edata.decode_imm(:u16, @endianness) end
  def decode_word( edata = @encoded) edata.decode_imm(:u32, @endianness) end
  def decode_xhalf(edata = @encoded) edata.edoced_imm((@intsize == 32 ? :u16 : :u32), @endianness) end
  def decode_xword(edata = @encoded) edata.decode_imm((@intsize == 32 ? :u32 : :u64), @endianness) end
  def encode_half(w)  Expression[w].encode(:u16, @endianness) end
  def encode_word(w)  Expression[w].encode(:u32, @endianness) end
  def encode_xhalf(w) Expression[w].encode((@intsize == 32 ? :u16 : :u32), @endianness) end
  def encode_xword(w) Expression[w].encode((@intsize == 32 ? :u32 : :u64), @endianness) end


  attr_accessor :header, :segments, :relocs, :intsize, :endianness

  def initialize(cpu=nil)
    @header = Header.new
    @sections = []
    if @cpu
      @intsize = @cpu.size
      @endianness = @cpu.endianness
    else
      @intsize = 32
      @endianness = :little
    end
    super(cpu)
  end

  def decode_header(off = 0)
    @encoded.ptr = off
    @header.decode(self)
    if @header.opthdr != 0
      @optheader = OptHeader.decode(self)
    end
    @header.nsec.times { @sections << Section.decode(self) }
  end

  def decode
    decode_header
    @sections.each { |s| s.encoded = @encoded[s.scnptr, s.size] }
  end

  def encode
    @encoded = EncodedData.new
    @encoded << @header.encode(self)
    @encoded << @optheader.encode(self) if @optheader
    @sections.each { |s| @encoded << s.encode(self) }
    va = @encoded.size
    binding = {}
    @sections.each { |s|
      if s.scnptr.kind_of? ::String
        binding[s.scnptr] = @encoded.size
      else
        raise 'scnptr too low' if @encoded.virtsize > s.scnptr
        @encoded.virtsize = s.scnptr
      end
      va = (va + 4096 - 1)/4096*4096
      if s.vaddr.kind_of? ::String
        binding[s.vaddr] = va
      else
        va = s.vaddr
      end
      binding.update s.encoded.binding(va)
      va += s.encoded.size
      @encoded << s.encoded
    }
    @encoded.fixup!(binding)
    @encoded.data
  end
end
end
