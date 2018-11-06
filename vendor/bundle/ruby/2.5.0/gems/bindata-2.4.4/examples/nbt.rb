require 'bindata'

# An example reader for Minecraft's NBT format.
# http://www.minecraft.net/docs/NBT.txt
#
# This is an example of how to write a BinData
# declaration for a recursively defined file format.
module Nbt

  TAG_NAMES = {
     0 => "End",
     1 => "Byte",
     2 => "Short",
     3 => "Int",
     4 => "Long",
     5 => "Float",
     6 => "Double",
     7 => "Byte_Array",
     8 => "String",
     9 => "List",
    10 => "Compound"
  }

  # NBT.txt line 25
  class TagEnd < BinData::Primitive
    def get; ""; end
    def set(v); end

    def to_formatted_s(indent = 0); to_s; end
  end

  # NBT.txt line 31
  class TagByte < BinData::Int8
    def to_formatted_s(indent = 0); to_s; end
  end

  # NBT.txt line 34
  class TagShort < BinData::Int16be
    def to_formatted_s(indent = 0); to_s; end
  end

  # NBT.txt line 37
  class TagInt < BinData::Int32be
    def to_formatted_s(indent = 0); to_s; end
  end

  # NBT.txt line 40
  class TagLong < BinData::Int64be
    def to_formatted_s(indent = 0); to_s; end
  end

  # NBT.txt line 43
  class TagFloat < BinData::FloatBe
    def to_formatted_s(indent = 0); to_s; end
  end

  # NBT.txt line 46
  class TagDouble < BinData::DoubleBe
    def to_formatted_s(indent = 0); to_s; end
  end

  # NBT.txt line 49
  class TagByteArray < BinData::Record
    int32be :len,  value: -> { data.length }
    string  :data, read_length: :len

    def to_formatted_s(indent = 0)
      "[#{len} bytes]"
    end
  end

  # NBT.txt line 53
  class TagString < BinData::Primitive
    int16be :len,  value: -> { data.length }
    string  :data, read_length: :len

    def get
      self.data
    end

    def set(v)
      self.data = v
    end

    def to_formatted_s(indent = 0); to_s; end
  end

  ## Payload is the most important class to understand.
  ## This abstraction allows recursive formats.
  ## eg. lists can contain lists can contain lists.

  # Forward references used by Payload
  class TagCompound < BinData::Record; end
  class TagList < BinData::Record; end

  # NBT.txt line 10
  class Payload < BinData::Choice
    tag_end        0
    tag_byte       1
    tag_short      2
    tag_int        3
    tag_long       4
    tag_float      5
    tag_double     6
    tag_byte_array 7
    tag_string     8
    tag_list       9
    tag_compound   10
  end

  # NBT.txt line 6, 27
  class NamedTag < BinData::Record
    int8 :tag_id
    tag_string :name,    onlyif: :not_end_tag?
    payload    :payload, onlyif: :not_end_tag?, selection: :tag_id

    def not_end_tag?
      tag_id != 0
    end

    def to_formatted_s(indent = 0)
      "  " * indent +
      "TAG_#{TAG_NAMES[tag_id]}(\"#{name}\"): " +
      payload.to_formatted_s(indent) + "\n"
    end
  end

  # NBT.txt line 57
  class TagList < BinData::Record
    int8    :tag_id
    int32be :len,  value: -> { data.length }
    array   :data, initial_length: :len do
      payload selection: :tag_id
    end

    def to_formatted_s(indent = 0)
      pre = "  " * indent
      tag_type = "TAG_#{TAG_NAMES[tag_id]}"

      "#{len} entries of type #{tag_type}\n" +
      pre + "{\n" +
        data.collect { |el| "  #{pre}#{tag_type}: #{el.to_formatted_s(indent + 1)}\n" }.join("") +
      pre + "}"
    end
  end

  # NBT.txt line 63
  class TagCompound < BinData::Record
    array :data, read_until: -> { element.tag_id == 0 } do
      named_tag
    end

    def to_formatted_s(indent = 0)
      pre = "  " * indent
      "#{data.length - 1} entries\n" +
      pre + "{\n" +
        data[0..-2].collect { |el| el.to_formatted_s(indent + 1) }.join("") +
      pre + "}"
    end
  end

  # NBT.txt line 3
  class Nbt < NamedTag
    def self.read(io)
      require 'zlib'
      super(Zlib::GzipReader.new(io))
    end
  end
end

if $0 == __FILE__
  require 'stringio'

  bigtest_nbt = StringIO.new "\037\213\b\000\000\000\000\000\000\003\355T\317O\032A\024~\302\002\313\226\202\261\304\020c\314\253\265\204\245\333\315B\021\211\261\210\026,\232\r\032\330\2501\206\270+\303\202.\273fw\260\361\324K{lz\353?\323#\177C\317\275\366\277\240\303/{i\317\275\3602\311\367\346\275o\346{o&y\002\004TrO,\016x\313\261M\215x\364\343pb>\b{\035\307\245\223\030\017\202G\335\356\204\002b\265\242\252\307xv\\W\313\250U\017\e\310\326\036j\225\206\206\r\255~X{\217\203\317\203O\203o\317\003\020n[\216>\276\2458Ld\375\020\352\332t\246\#@\334f.i\341\265\323\273s\372v\v)\333\v\340\357\350=\0368[\357\021\bV\365\336]\337\v@\340^\267\372d\267\004\000\214ALs\306\bUL\323 .}\244\300\310\302\020\263\272\336X\vS\243\356D\216E\0030\261'S\214L\361\351\024\243S\214\205\341\331\237\343\263\362D\201\245|3\335\330\273\307\252u\023_(\034\b\327.\321Y?\257\035\e`!Y\337\372\361\005\376\301\316\374\235\275\000\274\361@\311\370\205B@F\376\236\353\352\017\223:h\207`\273\35327\243(\n\216\273\365\320ic\312N\333\351\354\346\346+;\275%\276dI\t=\252\273\224\375\030~\350\322\016\332o\025L\261h>+\341\233\234\204\231\274\204\005\teY\026E\000\377/(\256/\362\302\262\244.\035 wZ;\271\214\312\347)\337QA\311\026\265\305m\241*\255,\3051\177\272z\222\216^\235_\370\022\005#\e\321\366\267w\252\315\225r\274\236\337X]K\227\256\222\027\271D\320\200\310\372>\277\263\334T\313\aun\243\266vY\222\223\251\334QP\231k\3145\346\032\377W#\bB\313\351\e\326x\302\354\376\374z\373}x\323\204\337\324\362\244\373\b\006\000\000"

  nbt = Nbt::Nbt.read(bigtest_nbt)
  puts nbt.to_formatted_s
end
