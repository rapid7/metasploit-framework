#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'

module Metasm
# Similar to Shellcode, with distinct sections per memory permission (R / RW / RX)
# encoding-side only
class Shellcode_RWX < ExeFormat
  # the array of source elements (Instr/Data etc)
  attr_accessor :source_r, :source_w, :source_x
  # base address per section
  attr_accessor :base_r, :base_w, :base_x
  # encodeddata
  attr_accessor :encoded_r, :encoded_w, :encoded_x

  def initialize(cpu=nil)
    @base_r = @base_w = @base_x = nil
    @encoded_r = EncodedData.new
    @encoded_w = EncodedData.new
    @encoded_x = EncodedData.new

    super(cpu)
  end

  def parse_init
    @source_r = []
    @source_w = []
    @source_x = []
    @cursource = @source_x
    super()
  end

  # allows definition of the base address
  def parse_parser_instruction(instr)
    case instr.raw.downcase
    when '.base', '.baseaddr', '.base_addr'
      # ".base_addr <expression>"
      # expression should #reduce to integer
      @lexer.skip_space
      raise instr, 'syntax error' if not base = Expression.parse(@lexer).reduce
      raise instr, 'syntax error' if tok = @lexer.nexttok and tok.type != :eol
      if @cursource.equal?(@source_r)
        @base_r = base
      elsif @cursource.equal?(@source_w)
        @base_w = base
      elsif @cursource.equal?(@source_x)
        @base_x = base
      else raise instr, "Where am I ?"
      end
    when '.rdata', '.rodata'
      @cursource = @source_r
    when '.data', '.bss'
      @cursource = @source_w
    when '.text'
      @cursource = @source_x
    else super(instr)
    end
  end

  # encodes the source found in self.source
  # appends it to self.encoded
  # clears self.source
  # the optional parameter may contain a binding used to fixup! self.encoded
  # uses self.base_addr if it exists
  def assemble(*a)
    parse(*a) if not a.empty?
    @encoded_r << assemble_sequence(@source_r, @cpu); @source_r.clear
    @encoded_w << assemble_sequence(@source_w, @cpu); @source_w.clear
    @encoded_x << assemble_sequence(@source_x, @cpu); @source_x.clear
    self
  end

  def encode(binding={})
    bd = {}
    bd.update @encoded_r.binding(@base_r)
    bd.update @encoded_w.binding(@base_w)
    bd.update @encoded_x.binding(@base_x)
    bd.update binding if binding.kind_of?(Hash)
    @encoded_r.fixup bd
    @encoded_w.fixup bd
    @encoded_x.fixup bd
    self
  end
  alias fixup encode

  # resolve inter-section xrefs, raise if unresolved relocations remain
  # call this when you have assembled+allocated memory for every section
  def fixup_check(base_r=nil, base_w=nil, base_x=nil, bd={})
    if base_r.kind_of?(Hash)
      bd = base_r
      base_r = nil
    end
    @base_r = base_r if base_r
    @base_w = base_w if base_w
    @base_x = base_x if base_x
    fixup bd
    ed = EncodedData.new << @encoded_r << @encoded_w << @encoded_x
    raise ["Unresolved relocations:", ed.reloc.map { |o, r| "#{r.target} " + (Backtrace.backtrace_str(r.backtrace) if r.backtrace).to_s }].join("\n") if not ed.reloc.empty?
    self
  end

  def encode_string(*a)
    encode(*a)
    ed = EncodedData.new << @encoded_r << @encoded_w << @encoded_x
    ed.fixup(ed.binding)
    raise ["Unresolved relocations:", ed.reloc.map { |o, r| "#{r.target} " + (Backtrace.backtrace_str(r.backtrace) if r.backtrace).to_s }].join("\n") if not ed.reloc.empty?
    ed.data
  end
end
end
