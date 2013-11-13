#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'
require 'metasm/parse'
require 'metasm/encode'
require 'metasm/decode'
require 'metasm/exe_format/serialstruct'
require 'metasm/os/main'	# VirtualFile

module Metasm
class ExeFormat
  # creates a new instance, populates self.encoded with the supplied string
  def self.load(str, *a, &b)
    e = new(*a, &b)
    if str.kind_of?(EncodedData); e.encoded = str
    else e.encoded << str
    end
    e
  end

  # same as load, used by AutoExe
  def self.autoexe_load(*x, &b)
    load(*x, &b)
  end

  attr_accessor :filename

  # same as +load+, but from a file
  # uses VirtualFile if available
  def self.load_file(path, *a, &b)
    e = load(VirtualFile.read(path), *a, &b)
    e.filename ||= path
    e
  end

  # +load_file+ then decode
  def self.decode_file(path, *a, &b)
    e = load_file(path, *a, &b)
    e.decode if not e.instance_variables.map { |iv| iv.to_s }.include?("@disassembler")
    e
  end

  # +load_file+ then decode header
  def self.decode_file_header(path, *a, &b)
    e = load_file(path, *a, &b)
    e.decode_header
    e
  end

  def self.decode(raw, *a, &b)
    e = load(raw, *a, &b)
    e.decode
    e
  end

  def self.decode_header(raw, *a, &b)
    e = load(raw, *a, &b)
    e.decode_header
    e
  end

  def load(str)
    if str.kind_of?(EncodedData); @encoded = str
    else @encoded << str
    end
    self
  end

  def load_file(path)
    @filename ||= path
    load(VirtualFile.read(path))
  end

  def decode_file(path)
    load_file(path)
    decode
    self
  end

  def decode_file_header(path)
    load_file(path)
    decode_header
    self
  end

  # creates a new object using the specified cpu, parses the asm source, and assemble
  def self.assemble(cpu, source, file='<unk>', lineno=1)
    source, cpu = cpu, source if source.kind_of? CPU
    e = new(cpu)
    e.assemble(source, file, lineno)
    e
  end

  # same as #assemble, reads asm source from the specified file
  def self.assemble_file(cpu, filename)
    filename, cpu = cpu, filename if filename.kind_of? CPU
    assemble(cpu, File.read(filename), filename, 1)
  end

  # parses a bunch of standalone C code, compile and assemble it
  def compile_c(source, file='<unk>', lineno=1)
    cp = @cpu.new_cparser
    tune_cparser(cp)
    cp.parse(source, file, lineno)
    read_c_attrs cp if respond_to? :read_c_attrs
    asm_source = @cpu.new_ccompiler(cp, self).compile
    puts asm_source if $DEBUG
    assemble(asm_source, 'C compiler output', 1)
    c_set_default_entrypoint
  end

  # creates a new object using the specified cpu, parse/compile/assemble the C source
  def self.compile_c(cpu, source, file='<unk>', lineno=1)
    source, cpu = cpu, source if source.kind_of? CPU
    e = new(cpu)
    e.compile_c(source, file, lineno)
    e
  end

  def self.compile_c_file(cpu, filename)
    filename, cpu = cpu, filename if filename.kind_of? CPU
    compile_c(cpu, File.read(filename), filename, 1)
  end

  # add directive to change the current assembler section to the assembler source +src+
  def compile_setsection(src, section)
    src << section
  end

  # prepare a preprocessor before it reads any source, should define macros to identify the fileformat
  def tune_prepro(l)
  end

  # prepare a cparser
  def tune_cparser(cp)
    tune_prepro(cp.lexer)
  end

  # this is called once C code is parsed, to handle C attributes like export/import/init etc
  def read_c_attrs(cp)
  end

  # should setup a default entrypoint for C code, including preparing args for main() etc
  def c_set_default_entrypoint
  end

  attr_writer :disassembler	# custom reader
  def disassembler
    @disassembler ||= init_disassembler
  end

  # returns the exe disassembler
  # if it does not exist, creates one, and feeds it with the exe sections
  def init_disassembler
    @disassembler ||= Disassembler.new(self)
    @disassembler.cpu ||= cpu
    each_section { |edata, base|
      edata ||= EncodedData.new
      @disassembler.add_section edata, base
    }
    @disassembler
  end

  # disassembles the specified entrypoints
  # initializes the disassembler if needed
  # uses get_default_entrypoints if the argument list is empty
  # returns the disassembler
  def disassemble(*entrypoints)
    entrypoints = get_default_entrypoints if entrypoints.empty?
    disassembler.disassemble(*entrypoints)
    @disassembler
  end

  # disassembles the specified entrypoints without backtracking
  # initializes the disassembler if needed
  # uses get_default_entrypoints if the argument list is empty
  # returns the disassembler
  def disassemble_fast_deep(*entrypoints)
    entrypoints = get_default_entrypoints if entrypoints.empty?
    disassembler.disassemble_fast_deep(*entrypoints)
    @disassembler
  end

  # returns a list of entrypoints to disassemble (program entrypoint, exported functions...)
  def get_default_entrypoints
    []
  end

  # encodes the executable as a string, checks that all relocations are
  # resolved, and returns the raw string version
  def encode_string(*a)
    encode(*a)
    raise ["Unresolved relocations:", @encoded.reloc.map { |o, r| "#{r.target} " + (Backtrace.backtrace_str(r.backtrace) if r.backtrace).to_s }].join("\n") if not @encoded.reloc.empty?
    @encoded.data
  end

  # saves the result of +encode_string+ in the specified file
  # overwrites existing files
  def encode_file(path, *a)
    encode_string(*a)
    File.open(path, 'wb') { |fd| fd.write(@encoded.data) }
  end

  # returns the address at which a given file offset would be mapped
  def addr_to_fileoff(addr)
    addr
  end

  # returns the file offset where a mapped byte comes from
  def fileoff_to_addr(foff)
    foff
  end

  def shortname; self.class.name.split('::').last.downcase; end

module IntToHash
  # converts a constant name to its numeric value using the hash
  # {1 => 'toto', 2 => 'tata'}: 'toto' => 1, 42 => 42, 'tutu' => raise
  def int_from_hash(val, hash)
    val.kind_of?(Integer) ? hash.index(val) || val : hash.index(val) or raise "unknown constant #{val.inspect}"
  end

  # converts an array of flag constants to its numeric value using the hash
  # {1 => 'toto', 2 => 'tata'}: ['toto', 'tata'] => 3, 'toto' => 2, 42 => 42
  def bits_from_hash(val, hash)
    val.kind_of?(Array) ? val.inject(0) { |val_, bitname| val_ | int_from_hash(bitname, hash) } : int_from_hash(val, hash)
  end

  # converts a numeric value to the corresponding constant name using the hash
  # {1 => 'toto', 2 => 'tata'}: 1 => 'toto', 42 => 42, 'tata' => 'tata', 'tutu' => raise
  def int_to_hash(val, hash)
    val.kind_of?(Integer) ? hash.fetch(val, val) : (hash.index(val) ? val : raise("unknown constant #{val.inspect}"))
  end

  # converts a numeric value to the corresponding array of constant flag names using the hash
  # {1 => 'toto', 2 => 'tata'}: 5 => ['toto', 4]
  def bits_to_hash(val, hash)
    (val.kind_of?(Integer) ? (hash.find_all { |k, v| val & k == k and val &= ~k }.map { |k, v| v } << val) : val.kind_of?(Array) ? val.map { |e| int_to_hash(e, hash) } : [int_to_hash(val, hash)]) - [0]
  end
end
  include IntToHash
end

class SerialStruct
  include ExeFormat::IntToHash
end
end
