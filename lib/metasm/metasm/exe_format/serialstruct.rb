#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

module Metasm
# a class representing a simple structure serialized in a binary
class SerialStruct
  # hash shared by all classes
  # key = class, value = array of fields
  # field = array [name, decode...]
  @@fields = {}
  NAME=0
  DECODE=1
  ENCODE=2
  DEFVAL=3
  ENUM=4
  BITS=5

class << self
  # defines a new field
  # adds an accessor
  def new_field(name, decode, encode, defval, enum=nil, bits=nil)
    if name
      attr_accessor name
      name = "@#{name}".to_sym
    end
    (@@fields[self] ||= []) << [name, decode, encode, defval, enum, bits]
  end

  # creates a field constructor for a simple integer
  # relies on exe implementing (en,de)code_#{type}
  def new_int_field(*types)
    recv = class << self ; self ; end
    types.each { |type|
      recv.send(:define_method, type) { |name, *args|
        new_field(name, "decode_#{type}".to_sym, "encode_#{type}".to_sym, args[0] || 0, args[1])
      }

      # shortcut to define multiple fields of this type with default values
      recv.send(:define_method, "#{type}s") { |*names|
        names.each { |name| send type, name }
      }
    }
  end

  # standard fields:

  # a fixed-size memory chunk
  def mem(name, len, defval='')
    new_field(name, lambda { |exe, me| exe.curencoded.read(len) }, lambda { |exe, me, val| val[0, len].ljust(len, 0.chr) }, defval)
  end
  # a fixed-size string, 0-padded
  def str(name, len, defval='')
    e = lambda { |exe, me, val| val[0, len].ljust(len, 0.chr) }
    d = lambda { |exe, me| v = exe.curencoded.read(len) ; v = v[0, v.index(?\0)] if v.index(?\0) ; v }
    new_field(name, d, e, defval)
  end
  # 0-terminated string
  def strz(name, defval='')
    d = lambda { |exe, me|
             ed = exe.curencoded
      ed.read(ed.data.index(?\0, ed.ptr)-ed.ptr+1).chop
    }
    e = lambda { |exe, me, val| val + 0.chr }
    new_field(name, d, e, defval)
  end

  # field access
  def fld_get(name)
    name = "@#{name}".to_sym
    @@fields[self].find { |f| f[NAME] == name }
  end

  # change the default for a field
  def fld_default(name, default=nil, &b)
    default ||= b
    fld_get(name)[DEFVAL] = default
  end
  def fld_enum(name, enum=nil, &b) fld_get(name)[ENUM] = enum||b end
  def fld_bits(name, bits=nil, &b) fld_get(name)[BITS] = bits||b end

  # define a bitfield: many fields inside a single word/byte/whatever
  # usage: bitfield :word, 0 => :lala, 1 => nil, 4 => :lolo, 8 => :foo
  #  => a bitfield read using exe.decode_word, containing 3 subfields:
  #   :lala (bits 0...1), (discard 3 bits), :lolo (bits 4...8), and :foo (bits 8..-1)
  #  fields default to 0
  def bitfield(inttype, h)
    # XXX encode/decode very not threadsafe ! this is a Georges Foreman Guarantee.
    # could use a me.instance_variable..

    # decode the value in a temp var
    d = lambda { |exe, me| @bitfield_val = exe.send("decode_#{inttype}") }
    # reset a temp var
    e = lambda { |exe, me, val| @bitfield_val = 0 ; nil }
    new_field(nil, d, e, nil)

    h = h.sort
    h.length.times { |i|
      # yay closure !
      # get field parameters
      next if not name = h[i][1]
      off = h[i][0]
      nxt = h[i+1]
      mask = (nxt ? (1 << (nxt[0]-off))-1 : -1)
      # read the field value from the temp var
      d = lambda { |exe, me| (@bitfield_val >> off) & mask }
      # update the temp var with the field value, return nil
      e = lambda { |exe, me, val| @bitfield_val |= (val & mask) << off ; nil }
             new_field(name, d, e, 0)
    }

    # free the temp var
    d = lambda { |exe, me| @bitfield_val = nil }
    # return encoded temp var
    e = lambda { |exe, me, val|
      val = @bitfield_val
      @bitfield_val = nil
      exe.send("encode_#{inttype}", val)
    }
    new_field(nil, d, e, nil)
  end

  # inject a hook to be run during the decoding process
  def decode_hook(before=nil, &b)
    idx = (before ? @@fields[self].index(fld_get(before)) : -1)
    @@fields[self].insert(idx, [nil, b])
  end
end	# class methods

  # standard int fields
  new_int_field :byte, :half, :word

  # set value of fields from argument list, runs int_to_hash if needed
  def initialize(*a)
    if not a.empty?
      a.zip(struct_fields.reject { |f| not f[NAME] }).each { |v, f|
        v = int_to_hash(v, f[ENUM]) if f[ENUM]
        v = bits_to_hash(v, f[BITS]) if f[BITS]
        instance_variable_set f[NAME], v
      }
    end
  end

  # returns this classes' field array
  # uses struct_specialized if defined (a method that returns another
  #  SerialStruct class whose fields should be used)
  def struct_fields(exe=nil)
    klass = self.class
    klass = struct_specialized(exe) if respond_to? :struct_specialized
    raise "SerialStruct: no fields for #{klass}" if $DEBUG and not @@fields[klass]
    @@fields[klass]
  end

  # decodes the fields from the exe
  def decode(exe, *args)
    struct_fields(exe).each { |f|
      case d = f[DECODE]
      when Symbol; val = exe.send(d, *args)
      when Array; val = exe.send(*d)
      when Proc; val = d[exe, self]
      when nil; next
      end
      next if not f[NAME]
      if h = f[ENUM]; h = h[exe, self] if h.kind_of? Proc; val = int_to_hash( val, h) end
      if h = f[BITS]; h = h[exe, self] if h.kind_of? Proc; val = bits_to_hash(val, h) end
      instance_variable_set(f[NAME], val)
    }
  end

  # initialize uninitialized fields
  def set_default_values(exe)
    struct_fields(exe).each { |f|
      if not f[NAME]
        f[DEFVAL][exe, self] if f[DEFVAL]
        next
      end
      # check existence to avoid a "warning: ivar @bla not initialized"
      next if instance_variables.map { |ivn| ivn.to_sym }.include?(f[NAME]) and instance_variable_get(f[NAME])
      val = f[DEFVAL]
      val = val[exe, self] if val.kind_of? Proc
      if val.kind_of? Integer and h = f[ENUM]; h = h[exe, self] if h.kind_of? Proc; val = int_to_hash( val, h) end
      if val.kind_of? Integer and h = f[BITS]; h = h[exe, self] if h.kind_of? Proc; val = bits_to_hash(val, h) end
      instance_variable_set(f[NAME], val)
    }
  end

  # sets default values, then encodes the fields, returns an EData
  def encode(exe, *a)
    set_default_values(exe, *a)

    ed = EncodedData.new
    struct_fields(exe).each { |f|
      if not f[NAME]
        ed << f[ENCODE][exe, self, nil] if f[ENCODE]
        next
      end
      val = instance_variable_get(f[NAME])
      if h = f[ENUM]; h = h[exe, self] if h.kind_of? Proc; val = int_from_hash( val, h) end
      if h = f[BITS]; h = h[exe, self] if h.kind_of? Proc; val = bits_from_hash(val, h) end
      case e = f[ENCODE]
      when Symbol; val = exe.send(e, val)
      when Array; val = exe.send(e, *val)
      when Proc; val = e[exe, self, val]
      when nil; next
      end
      ed << val
    }
    ed
  end

  # shortcut to create a new instance and decode it
  def self.decode(*a)
    s = new
    s.decode(*a)
    s
  end

  def dump(e, a)
    case e
    when Integer; e >= 0x100 ? '0x%X'%e : e
    when String; e.length > 64 ? e[0, 62].inspect+'...' : e.inspect
    when Array; '[' + e.map { |i| dump(i, a) }.join(', ') + ']'
    when SerialStruct; a.include?(e) ? '...' : e.to_s(a)
    else e.inspect
    end
  end

  # displays the struct content, ordered by fields
  def to_s(a=[])
    ivs = instance_variables.map { |iv| iv.to_sym }
    ivs = (struct_fields.to_a.map { |f| f[NAME] }.compact & ivs) | ivs
    "<#{self.class} " + ivs.map { |iv| "#{iv}=#{dump(instance_variable_get(iv), a+[self])}" }.join(' ') + ">"
  end
end

class ExeFormat
  def curencoded; encoded; end
  def decode_strz(ed = curencoded)
    if stop = ed.data.index(?\0, ed.ptr)
      ed.read(stop - ed.ptr + 1).chop
    else ''
    end
  end
end
end
