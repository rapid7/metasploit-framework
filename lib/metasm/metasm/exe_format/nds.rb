#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'


module Metasm
# Nintendo DS executable file format
class NDS < ExeFormat
  class Header < SerialStruct
    str :title, 12
    str :code, 4
    str :maker, 2
    bytes :unitcode, :encryptionselect, :devicetype
    mem :reserved1, 9
    bytes :version, :autostart
    words :arm9off, :arm9entry, :arm9addr, :arm9sz
    words :arm7off, :arm7entry, :arm7addr, :arm7sz
    words :fnameoff, :fnamesz, :fatoff, :fatsz
    words :arm9oloff, :arm9olsz, :arm7oloff, :arm7olsz
    words :romctrl1, :romtcrl2, :iconoff
    half :secureCRC
    half :romctrl3
    words :a9autoloadlist, :a7autoloadlist
    mem :secareadisable, 8
    words :endoff, :headersz
    mem :reserved4, 56
           mem :ninlogo, 156
    half :logoCRC, 0xcf56
    half :headerCRC
  end

  class Icon < SerialStruct
    halfs :version, :crc
    mem :reserved, 0x1c
    mem :bitmap, 0x200	# 32x32, 4x4 tiles, each 4x8 bytes, 4bit depth
    mem :palette, 0x20	# 16 colocs 16bits 0..0x7fff, 0 transparent (ignored)
    mem :title_jap, 0x100	# 16bit unicode
    mem :title_eng, 0x100
    mem :title_fre, 0x100
    mem :title_ger, 0x100
    mem :title_ita, 0x100
    mem :title_spa, 0x100
    mem :unused, 0x1c0

    attr_accessor :title_jap_short, :title_eng_short, :title_fre_short, :title_ger_short, :title_ita_short, :title_spa_short

    def decode(exe)
      super(exe)

      %w[jap eng fre ger ita spa].each { |lang|
        str = instance_variable_get("@title_#{lang}")
        uchrs = str.unpack('v*')
        str = str[0, uchrs.index(?\0).to_i*2]
        instance_variable_set("@title_#{lang}", str)
        str = str.unpack('v*').pack('C*')
        instance_variable_set("@title_#{lang}_short", str)
      }
    end
  end

  def encode_byte(val) Expression[val].encode(:u8,  @endianness) end
  def encode_half(val) Expression[val].encode(:u16, @endianness) end
  def encode_word(val) Expression[val].encode(:u32, @endianness) end
  def decode_byte(edata = @encoded) edata.decode_imm(:u8,  @endianness) end
  def decode_half(edata = @encoded) edata.decode_imm(:u16, @endianness) end
  def decode_word(edata = @encoded) edata.decode_imm(:u32, @endianness) end


  attr_accessor :header, :icon, :arm9, :arm7
  attr_accessor :files, :fat

  def initialize(endianness=:little)
    @endianness = endianness
    @encoded = EncodedData.new
  end

  # decodes the header from the current offset in self.encoded
  def decode_header
    @header = Header.decode(self)
  end

  def decode_icon
    @encoded.ptr = @header.iconoff
    @icon = Icon.decode(self)
  end

  def decode
    decode_header
    decode_icon
    @arm9 = @encoded[@header.arm9off, @header.arm9sz]
    @arm7 = @encoded[@header.arm7off, @header.arm7sz]
    @arm9.add_export('entrypoint', @header.arm9entry - @header.arm9addr)
    @arm7.add_export('entrypoint_arm7', @header.arm7entry - @header.arm7addr)
  end

  def decode_fat
    # decode the files section
    # it is just the tree structure of a file hierarchy
    # no indication whatsoever on where to find individual file content
    f = @encoded[@fnameoff, @fnamesz]
    f.ptr = 0
    idx = []
    # 1st word = size of index subsection
    idxsz = decode_word(f)
    f.ptr = 0
    # index seems to be an array of word, half, half (offset of name, index of name of first file, index of name of first subdir)
    (idxsz/8).times { idx << [decode_word(f), decode_half(f), decode_half(f)] }
    # follows a serie of filenames : 1-byte length, name
    # if length has high bit set, name is a directory, content = index[half following the name]
    dat = []
    idx.each { |off, idf, idd|
      f.ptr = off
      dat << []
      while (l = decode_byte(f)) > 0
        name = f.read(l&0x7f)
        if l & 0x80 > 0
          i = decode_half(f)
          dat.last << { name => i.to_s(16) }
        else
          dat.last << name
        end
      end
    }

    # build the tree from the serialized data
    # directory = array of [hash (subdirname => directory) or string (filename)]
    tree = dat.map { |dt| dt.map { |d| d.dup } }
    tree.each { |br|
      br.grep(Hash).each { |b|
        b.each { |k, v| b[k] = tree[v.to_i(16) & 0xfff] }
      }
    }
    tree = tree.first

    # flatten the tree to a list of fullpath
    iter = lambda { |ar, cur|
      ret = []
      ar.each { |elem|
        case elem
        when Hash; ret.concat iter[elem.values.first, cur + elem.keys.first + '/']
        else ret << (cur + elem)
        end
      }
      ret
    }

    @files = tree #iter[tree, '/']

    encoded.ptr = @fatoff
    @fat = encoded.read(@fatsz)
  end

  def cpu_from_headers
    ARM.new
  end

  def each_section
    yield @arm9, @header.arm9addr
    yield @arm7, @header.arm7addr
  end

  def get_default_entrypoints
    [@header.arm9entry, @header.arm7entry]
  end
end
end
