#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'


module Metasm
# Python preparsed module (.pyc)
class PYC < ExeFormat
  # 1 magic per python version...
  # file = MAGIC(u16) \r \n timestamp(u32) data
  MAGICS = [
    62211 # 62211 = python2.7a0
  ]

  class Header < SerialStruct
    half :version
    half :rn
    word :timestamp
  end

  def decode_half(edata=@encoded) edata.decode_imm(:u16, @endianness) end
  def decode_word(edata=@encoded) edata.decode_imm(:u32, @endianness) end
  def decode_long(edata=@encoded) edata.decode_imm(:i32, @endianness) end

  # file header
  attr_accessor :header
  # the marshalled object
  attr_accessor :root
  # list of all code objects
  attr_accessor :all_code

  def initialize()
    @endianness = :little
    @encoded = EncodedData.new
    super()
  end

  def decode_header
    @header = Header.decode(self)
  end

  def decode_pymarshal
    case c = @encoded.read(1)
    when '0' # NULL
      :null
    when 'N' # None
      nil
    when 'F' # False
      false
    when 'T' # True
      true
    #when 'S' # stopiter TODO
    #when '.' # ellipsis TODO
    when 'i' # long (i32)
      decode_long
    when 'I' # long (i64)
      decode_word | (decode_long << 32)
    when 'f' # float (ascii)
      @encoded.read(@encoded.read(1).unpack('C').first).to_f
    when 'g' # float (binary)
      @encoded.read(8).unpack('d').first	# XXX check
    when 'x' # complex (f f)
      { :type => :complex,
        :real => @encoded.read(@encoded.read(1).unpack('C').first).to_f,
        :imag => @encoded.read(@encoded.read(1).unpack('C').first).to_f }
    when 'y' # complex (g g)
      { :type => :complex,
        :real => @encoded.read(8).unpack('d').first,
        :imag => @encoded.read(8).unpack('d').first }
    when 'l' # long (i32?)
      decode_long
    when 's' # string: len (long), data
      @encoded.read(decode_long)
    when 't' # 'interned': string with possible backreference later
      s = @encoded.read(decode_long)
      @references << s
      s
    when 'R' # stringref (see 't')
      @references[decode_long]
    when '(' # tuple (frozen Array): length l*objs
      obj = []
      decode_long.times { obj << decode_pymarshal }
      obj
    when '[' # list (Array)
      obj = []
      decode_long.times { obj << decode_pymarshal }
      obj
    when '{' # dict (Hash)
      obj = {}
      loop do
        k = decode_pymarshal
        break if k == :null
        obj[k] = decode_pymarshal
      end
      { :type => hash, :hash => obj }	# XXX to avoid confusion with code, etc
    when 'c' # code
      # XXX format varies with version (header.signature)
      obj = {}
      obj[:type] = :code
      obj[:argcount] = decode_long
      #obj[:kwonly_argcount] = decode_long	# not in py2.7
      obj[:nlocals] = decode_long
      obj[:stacksize] = decode_long
      obj[:flags] = decode_long	# TODO bit-decode this one

      obj[:fileoff] = @encoded.ptr + 5	# XXX assume :code is a 's'
      obj[:code] = decode_pymarshal
      obj[:consts] = decode_pymarshal
      obj[:names] = decode_pymarshal
      obj[:varnames] = decode_pymarshal
      obj[:freevars] = decode_pymarshal
      obj[:cellvars] = decode_pymarshal
      obj[:filename] = decode_pymarshal
      obj[:name] = decode_pymarshal
      obj[:firstlineno] = decode_long
      obj[:lnotab] = decode_pymarshal
      @all_code << obj
      obj
    when 'u' # unicode
      @encoded.read(decode_long)
    #when '?' # unknown TODO
    #when '<' # set TODO
    #when '>' # set (frozen) TODO
    else
      raise "unsupported python marshal #{c.inspect}"
    end
  end

  def decode
    decode_header
    @all_code = []
    @references = []
    @root = decode_pymarshal
    @references = nil
  end

  def cpu_from_headers
    Python.new(self)
  end

  def each_section
    yield @encoded, 0
  end

  def get_default_entrypoints
    if @root.kind_of? Hash and @root[:type] == :code
      [@root[:fileoff]]
    else
      []
    end
  end

  # return the :code part which contains off
  def code_at_off(off)
    @all_code.find { |c| c[:fileoff] <= off and c[:fileoff] + c[:code].length > off }
  end
end
end
