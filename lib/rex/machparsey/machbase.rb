#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/struct2'

module Rex
module MachParsey

require 'rex/machparsey/exceptions'
require 'rex/struct2'

class GenericStruct
  attr_accessor :struct
  def initialize(_struct)
    self.struct = _struct
  end

  # Access a value
  def v
    struct.v
  end

  # Access a value by array
  def [](*args)
    struct[*args]
  end

  # Obtain an array of all fields
  def keys
    struct.keys
  end

  def method_missing(meth, *args)
    v[meth.to_s] || (raise NoMethodError.new, meth)
  end
end

class GenericHeader < GenericStruct
end

BITS_32 	= 0
BITS_64 	= 1
ENDIAN_LSB 	= 0
ENDIAN_MSB 	= 1

class MachBase

  MH_MAGIC 		= 0xfeedface
  MH_MAGIC_64 		= 0xfeedfacf
  MH_CIGAM 		= 0xcefaedfe
  MH_CIGAM_64 		= 0xcffaedfe
  MACH_HEADER_SIZE 	= 28
  MACH_HEADER_SIZE_64 	= 32


  MACH_HEADER_LSB = Rex::Struct2::CStructTemplate.new(
    ['uint32v', 'magic',	 0],
    ['uint32v', 'cputype',   0],
    ['uint32v', 'cpusubtype',0],
    ['uint32v', 'filetype',	 0],
    ['uint32v', 'ncmds',	 0],
    ['uint32v', 'sizeofcmds',0],
    ['uint32v', 'flags',	 0]
  )

  MACH_HEADER_MSB = Rex::Struct2::CStructTemplate.new(
    ['uint32n', 'magic',	 0],
    ['uint32n', 'cputype',   0],
    ['uint32n', 'cpusubtype',0],
    ['uint32n', 'filetype',	 0],
    ['uint32n', 'ncmds',	 0],
    ['uint32n', 'sizeofcmds',0],
    ['uint32n', 'flags',	 0]
  )


  MACH_HEADER_64_LSB = Rex::Struct2::CStructTemplate.new(
    ['uint32v', 'magic',	 0],
    ['uint32v', 'cputype',   0],
    ['uint32v', 'cpusubtype',0],
    ['uint32v', 'filetype',	 0],
    ['uint32v', 'ncmds',	 0],
    ['uint32v', 'sizeofcmds',0],
    ['uint32v', 'flags',	 0],
    ['uint32v', 'reserved',	 0]
  )

  MACH_HEADER_64_MSB = Rex::Struct2::CStructTemplate.new(
    ['uint32n', 'magic',	 0],
    ['uint32n', 'cputype',   0],
    ['uint32n', 'cpusubtype',0],
    ['uint32n', 'filetype',	 0],
    ['uint32n', 'ncmds',	 0],
    ['uint32n', 'sizeofcmds',0],
    ['uint32n', 'flags',	 0],
    ['uint32n', 'reserved',	 0]
  )

  #cpu types for Mach-O binaries
  CPU_TYPE_I386		= 0x7
  CPU_TYPE_X86_64		= 0x01000007
  CPU_TYPE_ARM 		= 0xC
  CPU_TYPE_POWERPC	= 0x12
  CPU_TYPE_POWERPC64	= 0x01000012

  CPU_SUBTYPE_LITTLE_ENDIAN 	= 0
  CPU_SUBTYPE_BIG_ENDIAN		= 1

  LC_SEGMENT	= 0x1     #/* segment of this file to be mapped */
  LC_SYMTAB	= 0x2     #/* link-edit stab symbol table info */
  LC_SYMSEG	= 0x3     #/* link-edit gdb symbol table info (obsolete) */
  LC_THREAD	= 0x4     #/* thread */
  LC_UNIXTHREAD   = 0x5     #/* unix thread (includes a stack) */
  LC_LOADFVMLIB   = 0x6     #/* load a specified fixed VM shared library */
  LC_IDFVMLIB     = 0x7     #/* fixed VM shared library identification */
  LC_IDENT        = 0x8     #/* object identification info (obsolete) */
  LC_FVMFILE      = 0x9     #/* fixed VM file inclusion (internal use) */
  LC_PREPAGE      = 0xa     #/* prepage command (internal use) */
  LC_DYSYMTAB     = 0xb     #/* dynamic link-edit symbol table info */
  LC_LOAD_DYLIB   = 0xc     #/* load a dynamicly linked shared library */
  LC_ID_DYLIB     = 0xd     #/* dynamicly linked shared lib identification */
  LC_LOAD_DYLINKER = 0xe    #/* load a dynamic linker */
  LC_ID_DYLINKER   = 0xf     #/* dynamic linker identification */
  LC_PREBOUND_DYLIB = 0x10  #/* modules prebound for a dynamicly */
  LC_SEGMENT_64	= 0x19    #/* segment of this file to be mapped */




  class MachHeader < GenericHeader
    attr_accessor :bits, :endian

    def initialize(rawdata)
      mach_header = MACH_HEADER_LSB.make_struct
      if !mach_header.from_s(rawdata)
        raise MachHeaderError, "Could't access Mach-O Magic", caller
      end

      if mach_header.v['magic'] == MH_MAGIC
        endian = ENDIAN_LSB
        bits = BITS_32
        mach_header = MACH_HEADER_LSB.make_struct
      elsif mach_header.v['magic'] == MH_CIGAM
        bits = BITS_32
        endian = ENDIAN_MSB
        mach_header = MACH_HEADER_MSB.make_struct
      elsif mach_header.v['magic'] == MH_MAGIC_64
        endian = ENDIAN_LSB
        bits = BITS_64
        mach_header = MACH_HEADER_LSB.make_struct
      elsif mach_header.v['magic'] == MH_CIGAM_64
        endian = ENDIAN_MSB
        bits = BITS_64
        mach_header = MACH_HEADER_MSB.make_struct
      else
        raise MachHeaderError, "Couldn't find Mach Magic", caller
      end

      if !mach_header.from_s(rawdata)
        raise MachHeaderError, "Could't process Mach-O Header", caller
      end

      self.struct = mach_header
      self.endian = endian
      self.bits = bits
    end
  end

  LOAD_COMMAND_SIZE = 8

  LOAD_COMMAND_LSB = Rex::Struct2::CStructTemplate.new(
    ['uint32v','cmd',0],
    ['uint32v','cmdsize',0]
  )

  LOAD_COMMAND_MSB = Rex::Struct2::CStructTemplate.new(
    ['uint32n','cmd',0],
    ['uint32n','cmdsize',0]
  )

  class LoadCommand < GenericHeader
    def initialize(rawdata, endian)

      if endian == ENDIAN_MSB
        load_command = LOAD_COMMAND_MSB.make_struct
      else
        load_command = LOAD_COMMAND_LSB.make_struct
      end

      if !load_command.from_s(rawdata)
        raise MachParseError, "Couldn't parse load command"
      end

      self.struct = load_command

    end
  end

  SEGMENT_COMMAND_SIZE = 56

  SEGMENT_COMMAND_LSB = Rex::Struct2::CStructTemplate.new(
    ['uint32v', 'cmd',  0],
    ['uint32v', 'cmdsize',  0],
    ['string',  'segname',  16, ''],
    ['uint32v', 'vmaddr', 0],
    ['uint32v', 'vmsize', 0],
    ['uint32v', 'fileoff',  0],
    ['uint32v', 'filesize', 0],
    ['uint32v', 'maxprot',  0],
    ['uint32v', 'initprot', 0],
    ['uint32v', 'nsects', 0],
    ['uint32v', 'flags',  0]
  )

  SEGMENT_COMMAND_MSB = Rex::Struct2::CStructTemplate.new(
    ['uint32n', 'cmd',  0],
    ['uint32n', 'cmdsize',  0],
    ['string',  'segname',  16, ''],
    ['uint32n', 'vmaddr', 0],
    ['uint32n', 'vmsize', 0],
    ['uint32n', 'fileoff',  0],
    ['uint32n', 'filesize', 0],
    ['uint32n', 'maxprot',  0],
    ['uint32n', 'initprot', 0],
    ['uint32n', 'nsects', 0],
    ['uint32n', 'flags',  0]
  )

  SEGMENT_COMMAND_SIZE_64 = 72

  SEGMENT_COMMAND_64_LSB = Rex::Struct2::CStructTemplate.new(
    ['uint32v', 'cmd',  0],
    ['uint32v', 'cmdsize',  0],
    ['string',  'segname',  16, ''],
    ['uint64v', 'vmaddr', 0],
    ['uint64v', 'vmsize', 0],
    ['uint64v', 'fileoff',  0],
    ['uint64v', 'filesize', 0],
    ['uint32v', 'maxprot',  0],
    ['uint32v', 'initprot', 0],
    ['uint32v', 'nsects', 0],
    ['uint32v', 'flags',  0]
  )

  SEGMENT_COMMAND_64_MSB = Rex::Struct2::CStructTemplate.new(
    ['uint32n', 'cmd',  0],
    ['uint32n', 'cmdsize',  0],
    ['string',  'segname',  16, ''],
    ['uint64n', 'vmaddr', 0],
    ['uint64n', 'vmsize', 0],
    ['uint64n', 'fileoff',  0],
    ['uint64n', 'filesize', 0],
    ['uint32n', 'maxprot',  0],
    ['uint32n', 'initprot', 0],
    ['uint32n', 'nsects', 0],
    ['uint32n', 'flags',  0]
  )

  class Segment < GenericHeader
    attr_accessor :_bits, :_endian

    def initialize(rawdata, bits, endian)
      self._bits = bits

      if bits == BITS_64
        if endian == ENDIAN_MSB
          segment_command = SEGMENT_COMMAND_64_MSB.make_struct
        else
          segment_command = SEGMENT_COMMAND_64_LSB.make_struct
        end
      else
        if endian == ENDIAN_MSB
          segment_command = SEGMENT_COMMAND_MSB.make_struct
        else
          segment_command = SEGMENT_COMMAND_LSB.make_struct
        end
      end
      if !segment_command.from_s(rawdata)
        raise MachParseError, "Couldn't parse segment command"
      end

      self.struct = segment_command
    end

    def Segname
      v['segname']
    end

    def Vmaddr
      v['vmaddr']
    end

    def Vmsize
      v['vmsize']
    end

    def FileOff
      v['fileoff']
    end

    def FileSize
      v['filesize']
    end
  end

  class Thread < GenericHeader
    def initialize(rawdata)
    end
  end
end

  FAT_MAGIC = 0xcafebabe
  FAT_CIGAM = 0xbebafeca
  FAT_HEADER_SIZE = 8

  FAT_HEADER_LSB = Rex::Struct2::CStructTemplate.new(
    ['uint32v', 'magic',	0],
    ['uint32v', 'nfat_arch',0]
  )

  FAT_HEADER_MSB = Rex::Struct2::CStructTemplate.new(
    ['uint32n', 'magic',	0],
    ['uint32n', 'nfat_arch',0]
  )


  FAT_ARCH_SIZE = 20

  FAT_ARCH_LSB = Rex::Struct2::CStructTemplate.new(
    ['uint32v', 'cpu_type',   0],
    ['uint32v', 'cpu_subtype',0],
    ['uint32v', 'offset',   0],
    ['uint32v', 'size',   0],
    ['uint32v', 'align',    0]
  )

  FAT_ARCH_MSB = Rex::Struct2::CStructTemplate.new(
    ['uint32n', 'cpu_type',   0],
    ['uint32n', 'cpu_subtype',0],
    ['uint32n', 'offset',   0],
    ['uint32n', 'size',   0],
    ['uint32n', 'align',    0]
  )


class FatBase

  class FatHeader < GenericHeader
    attr_accessor :nfat_arch, :endian, :exists

    def initialize(rawdata)
      fat_header = FAT_HEADER_LSB.make_struct
      if !fat_header.from_s(rawdata)
        #raise something
      end

      magic = fat_header.v['magic']
      if magic == FAT_MAGIC
        endian = ENDIAN_LSB
      elsif magic == FAT_CIGAM
        endian = ENDIAN_MSB
        fat_header = FAT_HEADER_MSB.make_struct
        if !fat_header.from_s(rawdata)
          raise FatHeaderError, "Could not parse FAT header"
        end
      else
        self.exists = 0
        return
      end

      self.nfat_arch = fat_header.v['nfat_arch']
      self.struct = fat_header
      self.endian = endian
    end
  end

  class FatArch < GenericHeader
    attr_accessor :cpu_type, :cpu_subtype, :offset, :size

    def initialize(rawdata, endian)
      if endian == ENDIAN_LSB
        fat_arch = FAT_ARCH_LSB.make_struct
      else
        fat_arch = FAT_ARCH_MSB.make_struct
      end

      if !fat_arch.from_s(rawdata)
        raise FatHeaderError, "Could not parse arch from FAT header"
      end

      self.cpu_type = fat_arch.v['cpu_type']
      self.cpu_subtype = fat_arch.v['cpu_subtype']
      self.offset = fat_arch.v['offset']
      self.size = fat_arch.v['size']
      self.struct = fat_arch
    end

  end

  class Thread < GenericHeader
    def initialize(rawdata)
    end
  end


end

end
end
