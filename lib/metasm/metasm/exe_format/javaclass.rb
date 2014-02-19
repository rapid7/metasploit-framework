#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'

module Metasm

class JavaClass < ExeFormat
  MAGIC = "\xCA\xFE\xBA\xBE"

  CONSTANT_TAG = {0x1 => 'Utf8',   0x3 => 'Integer',
      0x4 => 'Float',  0x5 => 'Long',
      0x6 => 'Double', 0x7 => 'Class',
      0x8 => 'String', 0x9 => 'Fieldref',
      0xa => 'Methodref', 0xb => 'InterfaceMethodref',
      0xc => 'NameAndType' }

  class SerialStruct < Metasm::SerialStruct
    new_int_field :u1, :u2, :u4
  end

  class Header < SerialStruct
    mem :magic, 4, MAGIC
    u2 :minor_version
    u2 :major_version
  end

  class ConstantPool < SerialStruct
    u2 :constant_pool_count
    attr_accessor :constant_pool

    def decode(c)
      super(c)

      @constant_pool = [nil]

      i = 1
      while i < @constant_pool_count
        entry = ConstantPoolInfo.decode(c)
        entry.idx = i
        @constant_pool << entry
        i += 1

        if entry.tag =~ /Long|Double/
          # we must insert a phantom cell
          # for long and double constants
          @constant_pool << nil
          i += 1
        end
      end
    end

    def encode(c)
      cp = super(c)

      @constant_pool.each { |entry|
        next if entry.nil?
        cp << entry.encode(c)
      }
      cp
    end

    def [](idx)
      @constant_pool[idx]
    end

    def []=(idx, val)
      raise 'cannot be used to add a cp entry' if @constant_pool[idx].nil?
      @constant_pool[idx] = val
    end
  end

  class ConstantPoolInfo < SerialStruct
    u1 :tag
    fld_enum :tag, CONSTANT_TAG
    attr_accessor :info, :idx

    def decode(c)
      super(c)

      case @tag
      when 'Utf8'
        @info = ConstantUtf8.decode(c)
      when /Integer|Float/
        @info = ConstantIntFloat.decode(c)
      when /Long|Double/
        @info = ConstantLongDouble.decode(c)
      when /Class|String/
        @info = ConstantIndex.decode(c)
      when /ref$/
        @info = ConstantRef.decode(c)
      when 'NameAndType'
        @info = ConstantNameAndType.decode(c)
      else
        raise 'unkown constant tag'
        return
      end
    end

    def encode(c)
      super(c) << @info.encode(c)
    end
  end

  class ConstantUtf8 < SerialStruct
    u2 :length
    attr_accessor :bytes

    def decode(c)
      super(c)
      @bytes = c.encoded.read(@length)
    end

    def encode(c)
      super(c) << @bytes
    end
  end

  class ConstantIntFloat < SerialStruct
    u4 :bytes
  end

  class ConstantLongDouble < SerialStruct
    u4 :high_bytes
    u4 :low_bytes
  end

  class ConstantIndex < SerialStruct
    u2 :index
  end

  class ConstantRef < SerialStruct
    u2 :class_index
    u2 :name_and_type_index
  end

  class ConstantNameAndType < SerialStruct
    u2 :name_index
    u2 :descriptor_index
  end

  class ClassInfo < SerialStruct
    u2 :access_flags
    u2 :this_class
    u2 :super_class
  end

  class Interfaces < SerialStruct
    u2 :interfaces_count
    attr_accessor :interfaces

    def decode(c)
      super(c)

      @interfaces = []
      @interfaces_count.times {
        @interfaces << ConstantIndex.decode(c)
      }
    end

    def encode(c)
      ret = super(c)

      @interfaces.each { |e|
        ret << e.encode(c)
      }
      ret
    end

    def [](idx)
      @interfaces[idx]
    end
  end

  class Fields < SerialStruct
    u2 :fields_count
    attr_accessor :fields

    def decode(c)
      super(c)
      @fields = []
      @fields_count.times {
        @fields << FieldMethodInfo.decode(c)
      }
    end

    def encode(c)
      ret = super(c)

      @fields.each { |e|
        ret << e.encode(c)
      }
      ret
    end

    def [](idx)
      @fields[idx]
    end
  end

  class Methods < SerialStruct
    u2 :methods_count
    attr_accessor :methods

    def decode(c)
      super(c)
      @methods = []
      @methods_count.times {
        @methods << FieldMethodInfo.decode(c)
      }
    end

    def encode(c)
      ret = super(c)

      @methods.each { |e|
        ret << e.encode(c)
      }
      ret
    end

    def [](idx)
      @methods[idx]
    end
  end

  class FieldMethodInfo < SerialStruct
    u2 :access_flags
    u2 :name_index
    u2 :descriptor_index
    attr_accessor :attributes

    def decode(c)
      super(c)
      @attributes = Attributes.decode(c)
    end

    def encode(c)
      super(c) << @attributes.encode(c)
    end
  end

  class Attributes < SerialStruct
    u2 :attributes_count
    attr_accessor :attributes

    def decode(c)
      super(c)

      @attributes = []
      @attributes_count.times { |i|
        @attributes << AttributeInfo.decode(c)
      }
    end

    def encode(c)
      ret = super(c)

      @attributes.each { |e|
        ret << e.encode(c)
      }
      ret
    end

    def [](idx)
      @attributes[idx]
    end
  end

  class AttributeInfo < SerialStruct
    u2 :attribute_name_index
    u4 :attribute_length
    attr_accessor :data

    def decode(c)
      super(c)
      @data = c.encoded.read(@attribute_length)
    end

    def encode(c)
      super(c) << @data
    end
  end

  def encode_u1(val) Expression[val].encode(:u8, @endianness) end
  def encode_u2(val) Expression[val].encode(:u16, @endianness) end
  def encode_u4(val) Expression[val].encode(:u32, @endianness) end
  def decode_u1(edata = @encoded) edata.decode_imm(:u8, @endianness) end
  def decode_u2(edata = @encoded) edata.decode_imm(:u16, @endianness) end
  def decode_u4(edata = @encoded) edata.decode_imm(:u32, @endianness) end

  attr_accessor :header, :constant_pool, :class_info, :interfaces, :fields, :methods, :attributes

  def initialize(endianness=:big)
    @endianness = endianness
    @encoded = EncodedData.new
    super()
  end

  def decode
    @header = Header.decode(self)
    @constant_pool = ConstantPool.decode(self)
    @class_info = ClassInfo.decode(self)
    @interfaces = Interfaces.decode(self)
    @fields = Fields.decode(self)
    @methods = Methods.decode(self)
    @attributes = Attributes.decode(self)
  end

  def encode
    @encoded = EncodedData.new
    @encoded << @header.encode(self)
    @encoded << @constant_pool.encode(self)
    @encoded << @class_info.encode(self)
    @encoded << @interfaces.encode(self)
    @encoded << @fields.encode(self)
    @encoded << @methods.encode(self)
    @encoded << @attributes.encode(self)
    @encoded.data
  end

  def cpu_from_headers
    raise 'JVM'
  end

  def each_section
    raise 'n/a'
  end

  def get_default_entrypoints
    []
  end

  def string_at(idx)
    loop do
      tmp = @constant_pool[idx].info
      return tmp.bytes if tmp.kind_of? ConstantUtf8
      idx = tmp.index
    end
  end

  def decode_methodref(mref)
    class_idx = mref.info.class_index
    nt_idx = mref.info.name_and_type_index
    name_idx = @constant_pool[nt_idx].info.name_index
    desc_idx = @constant_pool[nt_idx].info.descriptor_index

    string_at(class_idx) + '/' + string_at(name_idx) + string_at(desc_idx)
  end

  def cp_add(cpi, tag)
    cpe = ConstantPoolInfo.new
    cpe.tag = tag
    cpe.info = cpi
    cpe.idx = @constant_pool.constant_pool_count

    @constant_pool.constant_pool << cpe
    @constant_pool.constant_pool_count += 1
    @constant_pool.constant_pool_count += 1 if tag =~ /Long|Double/

    cpe.idx
  end

  def cp_find(tag)
    constant_pool.constant_pool.each { |e|
      next if !e or e.tag != tag
      if yield(e.info)
        return e.idx
      end
    }
    nil
  end


  def cp_auto_utf8(string)
    if idx = cp_find('Utf8') { |i| i.bytes == string }
      return idx
    end

    cpi = ConstantUtf8.new
    cpi.bytes = string
    cpi.length = string.length
    cp_add(cpi, 'Utf8')
  end

  def cp_auto_class(classname)
    if idx = cp_find('Class') { |i| string_at(i.index) == classname }
      return idx
    end

    cpi = ConstantIndex.new
    cpi.index = cp_auto_utf8(classname)
    cp_add(cpi, 'Class')
  end

  def cp_add_methodref(classname, name, descriptor)
    nat = ConstantNameAndType.new
    nat.name_index = cp_auto_utf8(name)
    nat.descriptor_index = cp_auto_utf8(descriptor)
    natidx = cp_add(nat, 'NameAndType')

    cpi = ConstantRef.new
    cpi.class_index = cp_auto_class(classname)
    cpi.name_and_type_index = natidx

    cp_add(cpi, 'Methodref')
  end

  def attribute_create(name, data)
    a = AttributeInfo.new
    a.attribute_name_index = cp_auto_utf8(name)
    a.attribute_length = data.size
    a.data = data
    a
  end
end
end
