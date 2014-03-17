#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'

module Metasm
# a shellcode is a simple sequence of instructions
class Shellcode < ExeFormat
  # the array of source elements (Instr/Data etc)
  attr_accessor :source
  # the base address of the shellcode (nil if unspecified)
  attr_accessor :base_addr

  def initialize(cpu=nil, base_addr=nil)
    @base_addr = base_addr
    @source = []
    super(cpu)
  end

  def parse_init
    @cursource = @source
    super()
  end

  # allows definition of the base address
  def parse_parser_instruction(instr)
    case instr.raw.downcase
    when '.base', '.baseaddr', '.base_addr'
      # ".base_addr <expression>"
      # expression should #reduce to integer
      @lexer.skip_space
      raise instr, 'syntax error' if not @base_addr = Expression.parse(@lexer).reduce
      raise instr, 'syntax error' if tok = @lexer.nexttok and tok.type != :eol
    else super(instr)
    end
  end

  def get_section_at(addr)
    base = @base_addr || 0
    if not addr.kind_of? Integer
      [@encoded, addr] if @encoded.ptr = @encoded.export[addr]
    elsif addr >= base and addr < base + @encoded.virtsize
      @encoded.ptr = addr - base
      [@encoded, addr]
    end
  end

  def each_section
    yield @encoded, (@base_addr || 0)
  end

  def addr_to_fileoff(addr)
    addr - (base_addr || 0)
  end

  def fileoff_to_addr(foff)
    foff + (base_addr || 0)
  end

  # encodes the source found in self.source
  # appends it to self.encoded
  # clears self.source
  # the optional parameter may contain a binding used to fixup! self.encoded
  # uses self.base_addr if it exists
  def assemble(*a)
    parse(*a) if not a.empty?
    @encoded << assemble_sequence(@source, @cpu)
    @source.clear
    encode
  end

  def encode(binding={})
    @encoded.fixup! binding
    @encoded.fixup @encoded.binding(@base_addr)
    @encoded.fill @encoded.rawsize
    self
  end

  def decode
  end

  def self.disassemble(cpu, str, eip=0)
    sc = decode(str, cpu)
    sc.disassemble(eip)
  end

  def init_disassembler
    d = super()
    d.function[:default] = @cpu.disassembler_default_func
    d
  end

  def compile_setsection(src, section)
  end

  def dump_section_header(addr, edata)
    ''
  end

  def get_default_entrypoints
    [@base_addr || 0]
  end

  # returns a virtual subclass of Shellcode whose cpu_from_headers will return cpu
  def self.withcpu(cpu)
    c = Class.new(self)
    c.send(:define_method, :cpu_from_headers) { cpu }
    c
  end
end
end
