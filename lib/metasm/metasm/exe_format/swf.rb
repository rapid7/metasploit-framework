#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'
begin
  require 'zlib'
rescue LoadError
end

module Metasm
class SWF < ExeFormat
  attr_accessor :signature, :version, :header, :chunks

  CHUNK_TYPE = {
    0 => 'End', 1 => 'ShowFrame', 2 => 'DefineShape', 3 => 'FreeCharacter',
    4 => 'PlaceObject', 5 => 'RemoveObject', 6 => 'DefineBits', 7 => 'DefineButton',
    8 => 'JPEGTables', 9 => 'SetBackgroundColor', 10 => 'DefineFont', 11 => 'DefineText',
    12 => 'DoAction', 13 => 'DefineFontInfo', 14 => 'DefineSound', 15 => 'StartSound',
    16 => 'StopSound', 17 => 'DefineButtonSound', 18 => 'SoundStreamHead', 19 => 'SoundStreamBlock',
    20 => 'DefineBitsLossless', 21 => 'DefineBitsJPEG2', 22 => 'DefineShape2', 23 => 'DefineButtonCxform',
    24 => 'Protect', 25 => 'PathsArePostScript', 26 => 'PlaceObject2',
    28 => 'RemoveObject2', 29 => 'SyncFrame', 31 => 'FreeAll',
    32 => 'DefineShape3', 33 => 'DefineText2', 34 => 'DefineButton2', 35 => 'DefineBitsJPEG3',
    36 => 'DefineBitsLossless2', 37 => 'DefineEditText', 38 => 'DefineVideo', 39 => 'DefineSprite',
    40 => 'NameCharacter', 41 => 'ProductInfo', 42 => 'DefineTextFormat', 43 => 'FrameLabel',
    44 => 'DefineBehavior', 45 => 'SoundStreamHead2', 46 => 'DefineMorphShape', 47 => 'FrameTag',
    48 => 'DefineFont2', 49 => 'GenCommand', 50 => 'DefineCommandObj', 51 => 'CharacterSet',
    52 => 'FontRef', 53 => 'DefineFunction', 54 => 'PlaceFunction', 55 => 'GenTagObject',
    56 => 'ExportAssets', 57 => 'ImportAssets', 58 => 'EnableDebugger', 59 => 'DoInitAction',
    60 => 'DefineVideoStream', 61 => 'VideoFrame', 62 => 'DefineFontInfo2', 63 => 'DebugID',
    64 => 'EnableDebugger2', 65 => 'ScriptLimits', 66 => 'SetTabIndex', 67 => 'DefineShape4',
    68 => 'DefineMorphShape2', 69 => 'FileAttributes', 70 => 'PlaceObject3', 71 => 'ImportAssets2',
    72 => 'DoABC', 76 => 'SymbolClass', 82 => 'DoABC2',
  }

  class SerialStruct < Metasm::SerialStruct
    new_int_field :u8, :u16, :u32, :f16, :f32
  end

  class Rectangle < SerialStruct
    virtual :nbits, :xmin, :xmax, :ymin, :ymax

    def decode(swf)
      byte = swf.decode_u8
      bleft = 3
      @nbits = byte >> bleft
      @xmin, @xmax, @ymin, @ymax = (0..3).map {
        nb = @nbits
        v = 0
        while nb > bleft
          nb -= bleft
          v |= (byte & ((1<<bleft)-1)) << nb

          bleft = 8
          byte = swf.decode_u8
        end
        v |= (byte >> (bleft-nb)) & ((1<<nb)-1)
        bleft -= nb

        Expression.make_signed(v, @nbits)
      }
    end

    def set_default_values(swf)
      @xmin ||= 0
      @xmax ||= 31
      @ymin ||= 0
      @ymax ||= 31
      @nbits = (0..30).find { |nb|
        [@xmin, @xmax, @ymin, @ymax].all? { |v|
          if nb == 0
            v == 0
          elsif v >= 0
            # reserve sign bit
            (v >> (nb-1)) == 0
          else
            (v >> nb) == -1
          end
        } } || 31
    end

    def encode(swf)
      ed = super(swf)

      byte = @nbits << 3
      bleft = 3
      [@xmin, @xmax, @ymin, @ymax].each { |v|
        nb = @nbits
        while nb > bleft
          byte |= (v >> (nb-bleft)) & ((1<<bleft)-1)
          nb -= bleft

          ed << byte
          byte = 0
          bleft = 8
        end
        byte |= (v & ((1<<nb)-1)) << (bleft-nb)
        bleft -= nb
      }
      ed << byte if bleft < 8

      ed
    end
  end

  class Header < SerialStruct
    virtual :view
    u16 :framerate	# XXX bigendian...
    u16 :framecount

    def bswap_framerate(swf)
      @framerate = ((@framerate >> 8) & 0xff) | ((@framerate & 0xff) << 8) if swf.endianness == :little
    end

    def decode(swf)
      @view = Rectangle.decode(swf)
      super(swf)
      bswap_framerate(swf)
    end

    def encode(swf)
      ed = @view.encode(swf)
      bswap_framerate(swf)
      ed << super(swf)
      bswap_framerate(swf)
      ed
    end
  end

  class Chunk < SerialStruct
    bitfield :u16, 0 => :length_, 6 => :tag
    fld_enum :tag, CHUNK_TYPE
    attr_accessor :data

    def decode(swf)
      super(swf)
      @length = (@length_ == 0x3f ? swf.decode_u32 : @length_)
      @data = swf.encoded.read(@length)
    end

    def set_default_values(swf)
      @length = @data.length
      @length_ = [@length, 0x3f].min
    end

    def encode(swf)
      super(swf) <<
      (swf.encode_u32(@length) if @length >= 0x3f) <<
      @data
    end
  end

  def decode_u8( edata=@encoded) edata.decode_imm(:u8,  @endianness) end
  def decode_u16(edata=@encoded) edata.decode_imm(:u16, @endianness) end
  def decode_u32(edata=@encoded) edata.decode_imm(:u32, @endianness) end
  def decode_f16(edata=@encoded) edata.decode_imm(:i16, @endianness)/256.0 end
  def decode_f32(edata=@encoded) edata.decode_imm(:i32, @endianness)/65536.0 end
  def encode_u8(w)  Expression[w].encode(:u8,  @endianness) end
  def encode_u16(w) Expression[w].encode(:u16, @endianness) end
  def encode_u32(w) Expression[w].encode(:u32, @endianness) end
  def encode_f16(w) Expression[(w*256).to_i].encode(:u16, @endianness) end
  def encode_f32(w) Expression[(w*65536).to_i].encode(:u32, @endianness) end

  attr_accessor :endianness
  def initialize(cpu = nil)
    @endianness = :little
    @header = Header.new
    @chunks = []
    super(cpu)
  end

  def decode_header
    @signature = @encoded.read(3)
    @version = decode_u8
    @data_length = decode_u32
    case @signature
    when 'FWS'
    when 'CWS'
      # data_length = uncompressed data length
      data = @encoded.read(@encoded.length-8)
      data = Zlib::Inflate.inflate(data)
      @encoded = EncodedData.new(data)
    else raise InvalidExeFormat, "Bad signature #{@signature.inspect}"
    end
    @data_length = [@data_length, @encoded.length].min
    @header = Header.decode(self)
  end

  def decode
    decode_header
    while @encoded.ptr < @data_length
      @chunks << Chunk.decode(self)
    end
  end
end
end
