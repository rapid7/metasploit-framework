#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/exe_format/main'
require 'metasm/encode'
require 'metasm/decode'


module Metasm
# GameBoy ROM file format
class GameBoyRom < ExeFormat
  class Header < SerialStruct
    # starts at 0x104 in the file
    mem :logo, 0x30
    str :title, 0x10
    byte :sgb_flag
    byte :cartridge_type
    byte :rom_size	# n => (n+1) * 32k bytes
    byte :ram_size
    byte :destination_code
    byte :old_licensee_code
    byte :mask_rom_version
    byte :header_checksum
    byte :checksum_hi
    byte :checksum_lo
  end

  def encode_byte(val) Expression[val].encode(:u8,  @endianness) end
  def decode_byte(edata = @encoded) edata.decode_imm(:u8,  @endianness) end


  attr_accessor :header

  def initialize(cpu=nil)
    @endianness = (cpu ? cpu.endianness : :little)
    super(cpu)
  end

  def decode_header
    @encoded.ptr = 0x104
    @header = Header.decode(self)
  end

  def decode
    decode_header
    @encoded.add_export('entrypoint', 0x100)
  end

  def cpu_from_headers
    Z80.new('gb')
  end

  def each_section
    yield @encoded, 0
  end

  def get_default_entrypoints
    ['entrypoint']
  end
end
end
